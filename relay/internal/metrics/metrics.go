// Package metrics exposes the relay counters in the Prometheus text format.
//
// The label sets are fixed, so the counter maps are built once and only read
// afterwards: the hot path is a map lookup and an atomic add. All methods are
// no-ops on a nil *Metrics.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
)

const unknown = "unknown"

var (
	framesIn  = []string{"join", "leave", "list", "send", "offer", "withdraw", "claim", "grant", "refuse", unknown}
	framesOut = []string{"ok", "members", "sent", "deliver", "presence", "error", "granted", "claim_request"}
	codes     = []string{"offline", "not_joined", "replaced", "bad_frame", "too_large", "no_invite", "timeout"}
	// Invitation events: a claim received, granted or refused by the holder,
	// or left unanswered until the deadline.
	invites = []string{"claim", "grant", "refuse", "timeout"}
)

// Metrics holds the relay counters.
type Metrics struct {
	connections atomic.Int64
	in          map[string]*atomic.Uint64
	out         map[string]*atomic.Uint64
	refusals    map[string]*atomic.Uint64
	invites     map[string]*atomic.Uint64
	offers      atomic.Int64
}

// New returns a zeroed Metrics.
func New() *Metrics {
	return &Metrics{in: counters(framesIn), out: counters(framesOut), refusals: counters(codes), invites: counters(invites)}
}

func counters(keys []string) map[string]*atomic.Uint64 {
	m := make(map[string]*atomic.Uint64, len(keys))
	for _, k := range keys {
		m[k] = new(atomic.Uint64)
	}
	return m
}

func add(counters map[string]*atomic.Uint64, key string) {
	c, ok := counters[key]
	if !ok {
		c = counters[unknown]
	}
	if c != nil {
		c.Add(1)
	}
}

// ConnOpened and ConnClosed track the active WebSocket connections.
func (m *Metrics) ConnOpened() {
	if m != nil {
		m.connections.Add(1)
	}
}

func (m *Metrics) ConnClosed() {
	if m != nil {
		m.connections.Add(-1)
	}
}

// FrameIn counts a frame received from a client; types the relay does not
// know are counted under "unknown".
func (m *Metrics) FrameIn(typ string) {
	if m != nil {
		add(m.in, typ)
	}
}

// FrameOut counts a frame queued for a client.
func (m *Metrics) FrameOut(typ string) {
	if m != nil {
		add(m.out, typ)
	}
}

// Refusal counts a refusal, by error code.
func (m *Metrics) Refusal(code string) {
	if m != nil {
		add(m.refusals, code)
	}
}

// OffersChanged adds delta (possibly negative) to the active invitation offers.
func (m *Metrics) OffersChanged(delta int) {
	if m != nil {
		m.offers.Add(int64(delta))
	}
}

// Invite counts an invitation event: "claim", "grant", "refuse" or "timeout".
func (m *Metrics) Invite(event string) {
	if m != nil {
		add(m.invites, event)
	}
}

// Handler serves the Prometheus text exposition.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m.write(w)
	})
}

func (m *Metrics) write(w io.Writer) {
	fmt.Fprint(w, "# HELP xshell_relay_connections Connexions WebSocket actives.\n")
	fmt.Fprint(w, "# TYPE xshell_relay_connections gauge\n")
	fmt.Fprintf(w, "xshell_relay_connections %d\n", m.connections.Load())

	fmt.Fprint(w, "# HELP xshell_relay_offers Invitations actuellement proposées.\n")
	fmt.Fprint(w, "# TYPE xshell_relay_offers gauge\n")
	fmt.Fprintf(w, "xshell_relay_offers %d\n", m.offers.Load())

	fmt.Fprint(w, "# HELP xshell_relay_frames_total Trames échangées, par sens et par type (rate() donne des trames/s).\n")
	fmt.Fprint(w, "# TYPE xshell_relay_frames_total counter\n")
	writeCounters(w, "xshell_relay_frames_total", `direction="in",type=%q`, framesIn, m.in)
	writeCounters(w, "xshell_relay_frames_total", `direction="out",type=%q`, framesOut, m.out)

	fmt.Fprint(w, "# HELP xshell_relay_refusals_total Refus, par code d'erreur.\n")
	fmt.Fprint(w, "# TYPE xshell_relay_refusals_total counter\n")
	writeCounters(w, "xshell_relay_refusals_total", `code=%q`, codes, m.refusals)

	fmt.Fprint(w, "# HELP xshell_relay_invites_total Événements d'invitation : claim reçu, grant, refus du détenteur, délai dépassé.\n")
	fmt.Fprint(w, "# TYPE xshell_relay_invites_total counter\n")
	writeCounters(w, "xshell_relay_invites_total", `event=%q`, invites, m.invites)
}

func writeCounters(w io.Writer, name, labels string, keys []string, values map[string]*atomic.Uint64) {
	for _, k := range slices.Sorted(slices.Values(keys)) {
		fmt.Fprintf(w, "%s{"+labels+"} %d\n", name, k, values[k].Load())
	}
}
