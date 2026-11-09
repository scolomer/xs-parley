package ws

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/scolomer/omp-xshell/relay/internal/hub"
	"github.com/scolomer/omp-xshell/relay/internal/proto"
)

// conn is one served WebSocket connection. Three goroutines work on it: the
// reader (the HTTP handler goroutine) owns frame processing, the writer is the
// only one to write data frames, and the pinger sends keepalives.
type conn struct {
	srv  *Server
	ws   *websocket.Conn
	log  *slog.Logger
	sess *hub.Session

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce   sync.Once
	closing     chan struct{} // closed to make the writer flush, then close the socket
	closeCode   websocket.StatusCode
	closeReason string
	writerDone  chan struct{}
}

func (s *Server) serve(ws *websocket.Conn, log *slog.Logger) {
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	c := &conn{
		srv: s, ws: ws, log: log, ctx: ctx, cancel: cancel,
		closing: make(chan struct{}), writerDone: make(chan struct{}),
	}
	c.sess = hub.NewSession(log, s.cfg.QueueSize, cancel)

	// Frames are bounded by our own reader below, not by the library, so that
	// an oversized frame can be answered with error too_large.
	ws.SetReadLimit(-1)

	s.wg.Add(1)
	defer s.wg.Done()
	s.track(c, true)
	defer s.track(c, false)
	s.cfg.Metrics.ConnOpened()
	defer s.cfg.Metrics.ConnClosed()
	log.Info("connexion ouverte")

	go c.writeLoop()
	go c.pingLoop()
	c.readLoop()

	s.cfg.Hub.Disconnect(c.sess)
	cancel()
	<-c.writerDone
	_ = ws.CloseNow()
	log.Info("connexion fermée")
}

func (c *conn) readLoop() {
	for {
		typ, r, err := c.ws.Reader(c.ctx)
		if err != nil {
			return
		}
		data, err := io.ReadAll(io.LimitReader(r, proto.MaxFrame+1))
		if err != nil {
			return
		}
		if len(data) > proto.MaxFrame {
			c.srv.cfg.Metrics.FrameIn("unknown")
			c.refuse("", proto.CodeTooLarge, "trame supérieure à 64 Ko")
			c.closeAfterFlush(websocket.StatusMessageTooBig, "trame trop grande")
			// The writer flushes the error, then closes; wait for it.
			select {
			case <-c.writerDone:
			case <-c.ctx.Done():
			}
			return
		}
		if typ != websocket.MessageText {
			c.srv.cfg.Metrics.FrameIn("unknown")
			c.refuse("", proto.CodeBadFrame, "une trame est un message texte")
			continue
		}
		c.handle(data)
	}
}

func (c *conn) handle(data []byte) {
	h, m := c.srv.cfg.Hub, c.srv.cfg.Metrics
	in, err := proto.Parse(data)
	if err != nil {
		fe := err.(*proto.FrameError)
		m.FrameIn(fe.Type)
		c.refuse(fe.ID, proto.CodeBadFrame, fe.Message)
		return
	}
	m.FrameIn(in.Type)

	switch in.Type {
	case proto.TypeJoin:
		h.Join(c.sess, in.XshellID, in.FP, in.CertBox)
		h.Push(c.sess, proto.TypeOK, proto.OK(in.ID))
	case proto.TypeLeave:
		if e := h.Leave(c.sess, in.XshellID); e != nil {
			h.Refuse(c.sess, in.ID, e)
			return
		}
		h.Push(c.sess, proto.TypeOK, proto.OK(in.ID))
	case proto.TypeList:
		list, e := h.Members(c.sess, in.XshellID)
		if e != nil {
			h.Refuse(c.sess, in.ID, e)
			return
		}
		h.Push(c.sess, proto.TypeMembers, proto.MembersFrame(in.ID, in.XshellID, list))
	case proto.TypeSend:
		if e := h.Route(c.sess, in.XshellID, in.To, in.Env); e != nil {
			h.Refuse(c.sess, in.ID, e)
			return
		}
		h.Push(c.sess, proto.TypeSent, proto.Sent(in.ID))
	case proto.TypeOffer:
		c.ack(in.ID, h.Offer(c.sess, in.InviteID))
	case proto.TypeWithdraw:
		h.Withdraw(c.sess, in.InviteID)
		c.ack(in.ID, nil)
	case proto.TypeClaim:
		// The answer (granted or an error) comes later, from the hub.
		if e := h.Claim(c.sess, in.ID, in.InviteID, in.EPK, in.Req); e != nil {
			h.Refuse(c.sess, in.ID, e)
		}
	case proto.TypeGrant:
		c.ack(in.ID, h.Grant(c.sess, in.Claim, in.Box))
	case proto.TypeRefuse:
		h.RefuseClaim(c.sess, in.Claim)
		c.ack(in.ID, nil)
	}
}

// ack answers a frame with ok, or with the error e when it is not nil.
func (c *conn) ack(id string, e *hub.Error) {
	h := c.srv.cfg.Hub
	if e != nil {
		h.Refuse(c.sess, id, e)
		return
	}
	h.Push(c.sess, proto.TypeOK, proto.OK(id))
}

func (c *conn) refuse(id, code, message string) {
	c.srv.cfg.Hub.Refuse(c.sess, id, &hub.Error{Code: code, Message: message})
}

// closeAfterFlush asks the writer to send what is queued, then close the
// socket with the given status. Only the first call counts.
func (c *conn) closeAfterFlush(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		c.closeCode, c.closeReason = code, reason
		close(c.closing)
	})
}

// writeLoop is the only goroutine writing data frames to the socket.
func (c *conn) writeLoop() {
	defer close(c.writerDone)
	defer c.cancel()
	write := func(frame []byte) bool {
		ctx, cancel := context.WithTimeout(c.ctx, c.srv.cfg.WriteTimeout)
		defer cancel()
		if err := c.ws.Write(ctx, websocket.MessageText, frame); err != nil {
			c.log.Debug("écriture échouée", "error", err)
			return false
		}
		return true
	}
	for {
		select {
		case frame := <-c.sess.Out():
			if !write(frame) {
				return
			}
		case <-c.closing:
			for {
				select {
				case frame := <-c.sess.Out():
					if !write(frame) {
						return
					}
					continue
				default:
				}
				break
			}
			_ = c.ws.Close(c.closeCode, c.closeReason)
			return
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *conn) pingLoop() {
	ticker := time.NewTicker(c.srv.cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(c.ctx, c.srv.cfg.WriteTimeout)
			err := c.ws.Ping(ctx)
			cancel()
			if err != nil {
				c.log.Info("keepalive sans réponse", "error", err)
				c.cancel()
				return
			}
		}
	}
}
