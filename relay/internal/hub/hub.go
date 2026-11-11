// Package hub holds the relay state: parley_id → fp → (connection, cert_box).
//
// It implements the semantics of SPEC §6.3 and knows nothing about
// WebSockets: a Session is an outbound queue drained by one writer goroutine
// owned by the transport, so the hub never writes to a socket.
package hub

import (
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/scolomer/xs-parley/relay/internal/proto"
)

// Error is a protocol error to report to the client that caused it.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Recorder counts what the hub sends. *metrics.Metrics implements it; a nil
// Recorder is allowed.
type Recorder interface {
	FrameOut(typ string)
	Refusal(code string)
	OffersChanged(delta int)
	Invite(event string)
}

// Session is one client connection as seen by the hub.
type Session struct {
	log  *slog.Logger
	out  chan []byte
	kill func()

	// joined maps parley_id → declared fp; guarded by Hub.mu.
	joined map[string]string
	// offers is the set of invite_ids this connection offers, and claims the
	// pending claims it takes part in (as claimant or holder); both guarded
	// by Hub.mu. See invite.go.
	offers map[string]struct{}
	claims map[string]*pendingClaim
}

// NewSession returns a session whose outbound queue holds queue frames. kill
// is called, without blocking, when the queue overflows: a client too slow to
// follow is disconnected rather than allowed to stall the relay.
func NewSession(log *slog.Logger, queue int, kill func()) *Session {
	return &Session{log: log, out: make(chan []byte, queue), kill: kill,
		joined: map[string]string{}, offers: map[string]struct{}{}, claims: map[string]*pendingClaim{}}
}

// Out is the outbound queue; the transport drains it from a single goroutine.
func (s *Session) Out() <-chan []byte { return s.out }

func (s *Session) enqueue(frame []byte) bool {
	select {
	case s.out <- frame:
		return true
	default:
		s.log.Warn("file d'envoi pleine, déconnexion")
		s.kill()
		return false
	}
}

type member struct {
	sess    *Session
	certBox string
}

// Hub is the in-memory registry. A single mutex guards it: every operation
// is a few map accesses and non-blocking queue pushes.
type Hub struct {
	rec     Recorder
	mu      sync.Mutex
	parleys map[string]map[string]*member // parley_id → fp → member

	claimTimeout time.Duration
	offers       map[string]*Session      // invite_id → offering connection
	claims       map[string]*pendingClaim // claim → pending claim
}

// Option configures a Hub.
type Option func(*Hub)

// WithClaimTimeout sets how long a holder has to answer a claim_request
// (default DefaultClaimTimeout).
func WithClaimTimeout(d time.Duration) Option {
	return func(h *Hub) { h.claimTimeout = d }
}

// New returns an empty hub.
func New(rec Recorder, opts ...Option) *Hub {
	h := &Hub{
		rec: rec, parleys: map[string]map[string]*member{},
		claimTimeout: DefaultClaimTimeout,
		offers:       map[string]*Session{}, claims: map[string]*pendingClaim{},
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Push queues a frame of type typ for s and reports whether it was queued.
func (h *Hub) Push(s *Session, typ string, frame []byte) bool {
	if h.rec != nil {
		h.rec.FrameOut(typ)
	}
	return s.enqueue(frame)
}

// Refuse queues an error frame answering the frame identified by id (which
// may be empty) and counts the refusal.
func (h *Hub) Refuse(s *Session, id string, e *Error) {
	if h.rec != nil {
		h.rec.Refusal(e.Code)
	}
	h.Push(s, proto.TypeError, proto.Error(e.Code, id, "", e.Message))
}

func notJoined() *Error {
	return &Error{proto.CodeNotJoined, "cette connexion n'a pas rejoint cette parley"}
}

// Join registers (parleyID, fp) → (s, certBox).
//
//   - held by another connection: that connection is replaced and told so;
//   - held by s itself: only the cert_box changes (kem_pub renewal);
//   - s was already a member of the parley under another fp: that membership
//     is left first (presence offline), since a connection is one member.
//
// In every case the other members receive presence online with the new
// cert_box.
func (h *Hub) Join(s *Session, parleyID, fp, certBox string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if previous, ok := s.joined[parleyID]; ok && previous != fp {
		h.removeLocked(s, parleyID, previous)
	}
	members := h.parleys[parleyID]
	if members == nil {
		members = map[string]*member{}
		h.parleys[parleyID] = members
	}
	if old := members[fp]; old != nil && old.sess != s {
		delete(old.sess.joined, parleyID)
		s.log.Info("connexion remplacée", "parley_id", parleyID, "fp", fp)
		h.Push(old.sess, proto.TypeError, proto.Error(proto.CodeReplaced, "", parleyID,
			"empreinte reprise par une autre connexion"))
		if h.rec != nil {
			h.rec.Refusal(proto.CodeReplaced)
		}
	} else if old == nil {
		s.log.Info("membre en ligne", "parley_id", parleyID, "fp", fp)
	}
	members[fp] = &member{sess: s, certBox: certBox}
	s.joined[parleyID] = fp
	h.broadcastLocked(members, fp, proto.Presence(parleyID, fp, true, certBox))
}

// Leave removes s from the parley.
func (h *Hub) Leave(s *Session, parleyID string) *Error {
	h.mu.Lock()
	defer h.mu.Unlock()
	fp, ok := s.joined[parleyID]
	if !ok {
		return notJoined()
	}
	h.removeLocked(s, parleyID, fp)
	return nil
}

// Members lists the connected members of the parley, s included, ordered by fp.
func (h *Hub) Members(s *Session, parleyID string) ([]proto.Member, *Error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := s.joined[parleyID]; !ok {
		return nil, notJoined()
	}
	members := h.parleys[parleyID]
	list := make([]proto.Member, 0, len(members))
	for fp, m := range members {
		list = append(list, proto.Member{FP: fp, CertBox: m.certBox})
	}
	slices.SortFunc(list, func(a, b proto.Member) int {
		switch {
		case a.FP < b.FP:
			return -1
		case a.FP > b.FP:
			return 1
		}
		return 0
	})
	return list, nil
}

// Route delivers env, untouched, to the member of the parley declared as to.
func (h *Hub) Route(s *Session, parleyID, to string, env []byte) *Error {
	h.mu.Lock()
	defer h.mu.Unlock()
	from, ok := s.joined[parleyID]
	if !ok {
		return notJoined()
	}
	target := h.parleys[parleyID][to]
	if target == nil || !h.Push(target.sess, proto.TypeDeliver, proto.Deliver(parleyID, env)) {
		s.log.Info("destinataire hors ligne", "parley_id", parleyID, "fp", from, "to", to)
		return &Error{proto.CodeOffline, "destinataire hors ligne"}
	}
	return nil
}

// Disconnect removes s from every parley it joined, announcing it offline,
// and drops its invitation offers and claims.
func (h *Hub) Disconnect(s *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropInvitesLocked(s)
	for parleyID, fp := range s.joined {
		h.removeLocked(s, parleyID, fp)
	}
}

func (h *Hub) removeLocked(s *Session, parleyID, fp string) {
	members := h.parleys[parleyID]
	delete(s.joined, parleyID)
	if m := members[fp]; m == nil || m.sess != s {
		return
	}
	delete(members, fp)
	if len(members) == 0 {
		delete(h.parleys, parleyID)
	}
	s.log.Info("membre hors ligne", "parley_id", parleyID, "fp", fp)
	h.broadcastLocked(members, fp, proto.Presence(parleyID, fp, false, ""))
}

// broadcastLocked pushes frame to every member except the one named except.
func (h *Hub) broadcastLocked(members map[string]*member, except string, frame []byte) {
	for fp, m := range members {
		if fp != except {
			h.Push(m.sess, proto.TypePresence, frame)
		}
	}
}
