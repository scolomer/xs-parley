// Package ws serves the relay protocol over WebSocket (GET /ws).
package ws

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/scolomer/omp-xshell/relay/internal/hub"
	"github.com/scolomer/omp-xshell/relay/internal/metrics"
)

// Config configures a Server.
type Config struct {
	Hub     *hub.Hub
	Metrics *metrics.Metrics
	Log     *slog.Logger

	PingInterval time.Duration // default 25 s
	WriteTimeout time.Duration // default 10 s
	QueueSize    int           // outbound frames per connection, default 256
}

// Server upgrades and serves the WebSocket connections.
type Server struct {
	cfg Config

	ctx  context.Context // cancelled to cut every connection
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu    sync.Mutex
	conns map[*conn]struct{}
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 25 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 10 * time.Second
	}
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 256
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Server{cfg: cfg, ctx: ctx, stop: stop, conns: map[*conn]struct{}{}}
}

// ServeHTTP upgrades the request, then serves the connection until it ends.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := s.cfg.Log.With("ip", clientIP(r))

	// Clients are not browsers: any Origin is accepted.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		log.Warn("upgrade échoué", "error", err)
		return
	}
	s.serve(ws, log)
}

// Shutdown closes every connection with a going-away status, waits for them
// to finish, and cuts the stragglers when ctx is done.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	for c := range s.conns {
		c.closeAfterFlush(websocket.StatusGoingAway, "arrêt du relai")
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	s.stop()
	<-done
}

func (s *Server) track(c *conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// clientIP prefers Fly-Client-IP, set by the Fly proxy, over the peer address.
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("Fly-Client-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
