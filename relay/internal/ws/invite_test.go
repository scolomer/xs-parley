package ws_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scolomer/xs-parley/relay/internal/hub"
)

const (
	inviteA = "IIIIIIIIIIIIIIIIIIIIII"
	inviteB = "JJJJJJJJJJJJJJJJJJJJJJ"
)

// epkA is a canonical base64url encoding of 32 bytes (43 characters); reqA is
// an arbitrary base64url request.
var (
	epkA = strings.Repeat("Ab_-", 10) + "Abw"
	reqA = strings.Repeat("Qr_-9", 20)
)

// claimFrame is a valid claim frame carrying epkA and reqA.
func claimFrame(id, invite string) frame {
	return frame{"v": 1, "t": "claim", "id": id, "invite_id": invite, "epk": epkA, "req": reqA}
}

// offer makes c offer the invitation and waits for the ok.
func (c *client) offer(invite string) {
	c.t.Helper()
	c.send(frame{"v": 1, "t": "offer", "id": "o", "invite_id": invite})
	c.expect(frame{"t": "ok", "id": "o"})
}

// claimRequest waits for the claim_request pushed to the holder, checks that
// epkA and reqA were relayed as received, and returns its claim.
func claimRequest(holder *client) string {
	holder.t.Helper()
	got := holder.expect(frame{"t": "claim_request", "epk": epkA, "req": reqA})
	claim, _ := got["claim"].(string)
	if claim == "" {
		holder.t.Fatalf("no claim in %v", got)
	}
	return claim
}

func metricsText(t *testing.T, r *relay) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestInviteGrantEndToEndWithoutJoin(t *testing.T) {
	r := newRelay(t)
	holder, claimant := r.dial(t), r.dial(t)

	holder.offer(inviteA)
	claimant.send(claimFrame("c-42", inviteA))
	claim := claimRequest(holder)

	box := strings.Repeat("Ab_-9", 100)
	holder.send(frame{"v": 1, "t": "grant", "id": "g1", "claim": claim, "box": box})
	holder.expect(frame{"t": "ok", "id": "g1"})
	claimant.expect(frame{"t": "granted", "id": "c-42", "box": box})

	holder.send(frame{"v": 1, "t": "withdraw", "id": "w1", "invite_id": inviteA})
	holder.expect(frame{"t": "ok", "id": "w1"})
	holder.send(frame{"v": 1, "t": "withdraw", "id": "w2", "invite_id": inviteA})
	holder.expect(frame{"t": "ok", "id": "w2"})
	claimant.send(claimFrame("c2", inviteA))
	claimant.expect(frame{"t": "error", "code": "no_invite", "id": "c2"})

	text := metricsText(t, r)
	for _, want := range []string{
		"xsp_relay_offers 0",
		`xsp_relay_invites_total{event="claim"} 2`,
		`xsp_relay_invites_total{event="grant"} 1`,
		`xsp_relay_frames_total{direction="out",type="granted"} 1`,
		`xsp_relay_frames_total{direction="out",type="claim_request"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

func TestInviteRefuse(t *testing.T) {
	r := newRelay(t)
	holder, claimant := r.dial(t), r.dial(t)
	holder.offer(inviteA)
	claimant.send(claimFrame("c1", inviteA))
	claim := claimRequest(holder)
	holder.send(frame{"v": 1, "t": "refuse", "id": "r1", "claim": claim})
	holder.expect(frame{"t": "ok", "id": "r1"})
	claimant.expect(frame{"t": "error", "code": "no_invite", "id": "c1"})
}

func TestInviteClaimWithoutOfferAndUnknownGrant(t *testing.T) {
	r := newRelay(t)
	c := r.dial(t)
	c.send(claimFrame("c1", inviteB))
	c.expect(frame{"t": "error", "code": "no_invite", "id": "c1"})
	c.send(frame{"v": 1, "t": "grant", "id": "g1", "claim": "unknown", "box": "box"})
	c.expect(frame{"t": "error", "code": "no_invite", "id": "g1"})
}

func TestInviteHolderDisconnectsDuringClaim(t *testing.T) {
	r := newRelay(t)
	holder, claimant := r.dial(t), r.dial(t)
	holder.offer(inviteA)
	claimant.send(claimFrame("c1", inviteA))
	claimRequest(holder)
	_ = holder.ws.CloseNow()
	claimant.expect(frame{"t": "error", "code": "no_invite", "id": "c1"})
}

func TestInviteClaimTimesOut(t *testing.T) {
	r := newRelayWith(t, hub.WithClaimTimeout(50*time.Millisecond))
	holder, claimant := r.dial(t), r.dial(t)
	holder.offer(inviteA)
	claimant.send(claimFrame("c1", inviteA))
	claim := claimRequest(holder)
	claimant.expect(frame{"t": "error", "code": "timeout", "id": "c1"})
	// A grant after the deadline is too late.
	holder.send(frame{"v": 1, "t": "grant", "id": "g1", "claim": claim, "box": "box"})
	holder.expect(frame{"t": "error", "code": "no_invite", "id": "g1"})
	if text := metricsText(t, r); !strings.Contains(text, `xsp_relay_invites_total{event="timeout"} 1`) {
		t.Errorf("timeout not counted:\n%s", text)
	}
}

func TestInviteOfferLimits(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.offer(inviteA)
	b.send(frame{"v": 1, "t": "offer", "id": "o2", "invite_id": inviteA})
	b.expect(frame{"t": "error", "code": "bad_frame", "id": "o2"})

	for i := range hub.MaxOffers - 1 {
		a.offer(strings.Repeat(string(rune('a'+i)), 22))
	}
	a.send(frame{"v": 1, "t": "offer", "id": "o17", "invite_id": inviteB})
	a.expect(frame{"t": "error", "code": "bad_frame", "id": "o17"})
}

func TestInviteBadFrames(t *testing.T) {
	r := newRelay(t)
	c := r.dial(t)
	tests := []struct{ name, raw, wantID string }{
		{"offer without invite_id", `{"v":1,"t":"offer","id":"x"}`, "x"},
		{"offer short invite_id", `{"v":1,"t":"offer","id":"x","invite_id":"short"}`, "x"},
		{"claim invalid invite_id", `{"v":1,"t":"claim","id":"x","invite_id":"` + strings.Repeat("+", 22) + `","epk":"` + epkA + `","req":"` + reqA + `"}`, "x"},
		{"claim without epk", `{"v":1,"t":"claim","id":"x","invite_id":"` + inviteA + `","req":"` + reqA + `"}`, "x"},
		{"claim without req", `{"v":1,"t":"claim","id":"x","invite_id":"` + inviteA + `","epk":"` + epkA + `"}`, "x"},
		{"claim short epk", `{"v":1,"t":"claim","id":"x","invite_id":"` + inviteA + `","epk":"` + epkA[:42] + `","req":"` + reqA + `"}`, "x"},
		{"claim epk with padding", `{"v":1,"t":"claim","id":"x","invite_id":"` + inviteA + `","epk":"` + epkA + `=","req":"` + reqA + `"}`, "x"},
		{"claim empty req", `{"v":1,"t":"claim","id":"x","invite_id":"` + inviteA + `","epk":"` + epkA + `","req":""}`, "x"},
		{"claim req too long", `{"v":1,"t":"claim","id":"x","invite_id":"` + inviteA + `","epk":"` + epkA + `","req":"` + strings.Repeat("r", 4097) + `"}`, "x"},
		{"withdraw without id", `{"v":1,"t":"withdraw","invite_id":"` + inviteA + `"}`, ""},
		{"grant without box", `{"v":1,"t":"grant","id":"x","claim":"c"}`, "x"},
		{"grant box too long", `{"v":1,"t":"grant","id":"x","claim":"c","box":"` + strings.Repeat("b", 8193) + `"}`, "x"},
		{"grant claim invalid", `{"v":1,"t":"grant","id":"x","claim":"a b","box":"b"}`, "x"},
		{"refuse without claim", `{"v":1,"t":"refuse","id":"x"}`, "x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c.sendRaw(tc.raw)
			got := c.expect(frame{"t": "error", "code": "bad_frame"})
			if id, _ := got["id"].(string); id != tc.wantID {
				t.Fatalf("error id = %q, want %q", id, tc.wantID)
			}
		})
	}
	// A box of exactly 8192 characters is accepted (and no claim exists).
	c.sendRaw(`{"v":1,"t":"grant","id":"x","claim":"c","box":"` + strings.Repeat("b", 8192) + `"}`)
	c.expect(frame{"t": "error", "code": "no_invite", "id": "x"})
	// A req of exactly 4096 characters is accepted (and no offer exists).
	c.sendRaw(`{"v":1,"t":"claim","id":"x","invite_id":"` + inviteB + `","epk":"` + epkA + `","req":"` + strings.Repeat("r", 4096) + `"}`)
	c.expect(frame{"t": "error", "code": "no_invite", "id": "x"})
}
