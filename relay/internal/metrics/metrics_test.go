package metrics_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scolomer/xs-parley/relay/internal/metrics"
)

func TestExposition(t *testing.T) {
	m := metrics.New()
	m.ConnOpened()
	m.ConnOpened()
	m.ConnClosed()
	m.FrameIn("join")
	m.FrameIn("join")
	m.FrameIn("garbage") // counted as unknown
	m.FrameOut("deliver")
	m.Refusal("offline")
	m.Refusal("not-a-code") // ignored, must not panic
	m.Refusal("no_invite")
	m.OffersChanged(3)
	m.OffersChanged(-1)
	m.Invite("claim")
	m.Invite("grant")
	m.Invite("grant")
	m.Invite("not-an-event") // ignored, must not panic

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	text := string(body)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type = %q", ct)
	}
	for _, want := range []string{
		"# TYPE xsp_relay_connections gauge\nxsp_relay_connections 1\n",
		`xsp_relay_frames_total{direction="in",type="join"} 2`,
		`xsp_relay_frames_total{direction="in",type="unknown"} 1`,
		`xsp_relay_frames_total{direction="out",type="deliver"} 1`,
		`xsp_relay_refusals_total{code="offline"} 1`,
		`xsp_relay_refusals_total{code="replaced"} 0`,
		`xsp_relay_refusals_total{code="no_invite"} 1`,
		`xsp_relay_refusals_total{code="timeout"} 0`,
		"# TYPE xsp_relay_offers gauge\nxsp_relay_offers 2\n",
		`xsp_relay_invites_total{event="claim"} 1`,
		`xsp_relay_invites_total{event="grant"} 2`,
		`xsp_relay_invites_total{event="refuse"} 0`,
		`xsp_relay_invites_total{event="timeout"} 0`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}
