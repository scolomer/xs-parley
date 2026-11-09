package hub_test

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scolomer/omp-xshell/relay/internal/hub"
	"github.com/scolomer/omp-xshell/relay/internal/proto"
)

const (
	inv = "IIIIIIIIIIIIIIIIIIIIII"
	// epk is a canonical base64url encoding of 32 bytes; req is an opaque request.
	epk = "Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Abw"
	req = "Qr_-9Qr_-9"
)

func TestDefaultClaimTimeoutLeavesTimeToConfirm(t *testing.T) {
	if hub.DefaultClaimTimeout != 120*time.Second {
		t.Fatalf("DefaultClaimTimeout = %v, want 2m0s", hub.DefaultClaimTimeout)
	}
}

func inviteID(n int) string { return fmt.Sprintf("%022d", n) }

type fakeRecorder struct {
	offers  atomic.Int64
	invites map[string]*atomic.Int64
}

func newRecorder() *fakeRecorder {
	r := &fakeRecorder{invites: map[string]*atomic.Int64{}}
	for _, e := range []string{"claim", "grant", "refuse", "timeout"} {
		r.invites[e] = new(atomic.Int64)
	}
	return r
}
func (r *fakeRecorder) FrameOut(string)      {}
func (r *fakeRecorder) Refusal(string)       {}
func (r *fakeRecorder) OffersChanged(d int)  { r.offers.Add(int64(d)) }
func (r *fakeRecorder) Invite(event string)  { r.invites[event].Add(1) }
func (r *fakeRecorder) count(e string) int64 { return r.invites[e].Load() }

type decoded map[string]any

func nextFrame(t *testing.T, s *hub.Session) decoded {
	t.Helper()
	var f decoded
	if err := json.Unmarshal([]byte(next(t, s)), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func noFrame(t *testing.T, s *hub.Session) {
	t.Helper()
	select {
	case f := <-s.Out():
		t.Fatalf("unexpected frame: %s", f)
	default:
	}
}

func waitFrame(t *testing.T, s *hub.Session) decoded {
	t.Helper()
	select {
	case raw := <-s.Out():
		var f decoded
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("no frame after 5 s")
		return nil
	}
}

func wantError(t *testing.T, f decoded, code, id string) {
	t.Helper()
	if f["t"] != "error" || f["code"] != code || f["id"] != id {
		t.Fatalf("frame %v, want error %s id %q", f, code, id)
	}
}

func wantCode(t *testing.T, e *hub.Error, code string) {
	t.Helper()
	if e == nil || e.Code != code {
		t.Fatalf("error = %v, want %s", e, code)
	}
}

// claimed offers inv from holder, claims it from claimant, and returns the
// claim the holder received.
func claimed(t *testing.T, h *hub.Hub, holder, claimant *hub.Session) string {
	t.Helper()
	if e := h.Offer(holder, inv); e != nil {
		t.Fatal(e)
	}
	if e := h.Claim(claimant, "c1", inv, epk, req); e != nil {
		t.Fatal(e)
	}
	got := nextFrame(t, holder)
	if got["t"] != "claim_request" || got["invite_id"] != inv {
		t.Fatalf("holder received %v", got)
	}
	// The claimant's epk and req reach the holder as received.
	if got["epk"] != epk || got["req"] != req {
		t.Fatalf("epk/req not relayed as received: %v", got)
	}
	claim, _ := got["claim"].(string)
	if claim == "" {
		t.Fatalf("no claim in %v", got)
	}
	return claim
}

func TestOfferClaimGrantRelaysTheBoxAndKeepsTheClaimantId(t *testing.T) {
	rec := newRecorder()
	h := hub.New(rec)
	holder, claimant := session(16, nil), session(16, nil)
	claim := claimed(t, h, holder, claimant)
	noFrame(t, claimant)

	if e := h.Grant(holder, claim, "sealedBox_-9"); e != nil {
		t.Fatal(e)
	}
	got := nextFrame(t, claimant)
	if got["t"] != "granted" || got["id"] != "c1" || got["box"] != "sealedBox_-9" {
		t.Fatalf("claimant received %v", got)
	}
	// The relay does not retire the offer after a grant: that is the holder's job.
	if e := h.Claim(claimant, "c2", inv, epk, req); e != nil {
		t.Fatalf("second claim: %v", e)
	}
	if got := nextFrame(t, holder); got["t"] != "claim_request" {
		t.Fatalf("holder received %v", got)
	}
	if rec.offers.Load() != 1 || rec.count("claim") != 2 || rec.count("grant") != 1 {
		t.Fatalf("metrics: offers=%d claims=%d grants=%d", rec.offers.Load(), rec.count("claim"), rec.count("grant"))
	}
}

func TestClaimsAreRandomAndDistinct(t *testing.T) {
	h := hub.New(nil)
	holder, claimant := session(64, nil), session(64, nil)
	h.Offer(holder, inv)
	seen := map[string]bool{}
	for i := range 20 {
		if e := h.Claim(claimant, fmt.Sprint("c", i), inv, epk, req); e != nil {
			t.Fatal(e)
		}
		claim, _ := nextFrame(t, holder)["claim"].(string)
		if len(claim) != 22 || seen[claim] {
			t.Fatalf("claim %q is short or repeated", claim)
		}
		seen[claim] = true
	}
}

func TestRefuseAnswersTheClaimantNoInvite(t *testing.T) {
	rec := newRecorder()
	h := hub.New(rec)
	holder, claimant := session(16, nil), session(16, nil)
	claim := claimed(t, h, holder, claimant)
	h.RefuseClaim(holder, claim)
	wantError(t, nextFrame(t, claimant), "no_invite", "c1")
	if rec.count("refuse") != 1 {
		t.Fatalf("refuse count = %d", rec.count("refuse"))
	}
	// Idempotent, and the claim is gone.
	h.RefuseClaim(holder, claim)
	wantCode(t, h.Grant(holder, claim, "box"), proto.CodeNoInvite)
	noFrame(t, claimant)
}

func TestClaimWithoutOfferIsNoInvite(t *testing.T) {
	h := hub.New(nil)
	wantCode(t, h.Claim(session(16, nil), "c1", inv, epk, req), proto.CodeNoInvite)
}

func TestHolderDisconnectingFailsPendingClaimsAndDropsOffers(t *testing.T) {
	rec := newRecorder()
	h := hub.New(rec)
	holder, claimant, other := session(16, nil), session(16, nil), session(16, nil)
	claim := claimed(t, h, holder, claimant)
	h.Offer(holder, inviteID(2))
	h.Disconnect(holder)
	wantError(t, nextFrame(t, claimant), "no_invite", "c1")
	wantCode(t, h.Claim(other, "c9", inv, epk, req), proto.CodeNoInvite)
	wantCode(t, h.Grant(holder, claim, "box"), proto.CodeNoInvite)
	if rec.offers.Load() != 0 {
		t.Fatalf("offers = %d, want 0", rec.offers.Load())
	}
	// The offer can be taken over by another connection.
	if e := h.Offer(other, inv); e != nil {
		t.Fatal(e)
	}
}

func TestClaimantDisconnectingForgetsItsClaims(t *testing.T) {
	h := hub.New(nil)
	holder, claimant := session(16, nil), session(16, nil)
	claim := claimed(t, h, holder, claimant)
	h.Disconnect(claimant)
	wantCode(t, h.Grant(holder, claim, "box"), proto.CodeNoInvite)
	noFrame(t, holder)
}

func TestClaimTimesOut(t *testing.T) {
	rec := newRecorder()
	h := hub.New(rec, hub.WithClaimTimeout(20*time.Millisecond))
	holder, claimant := session(16, nil), session(16, nil)
	claim := claimed(t, h, holder, claimant)
	wantError(t, waitFrame(t, claimant), "timeout", "c1")
	if rec.count("timeout") != 1 {
		t.Fatalf("timeout count = %d", rec.count("timeout"))
	}
	wantCode(t, h.Grant(holder, claim, "box"), proto.CodeNoInvite)
	noFrame(t, claimant)
}

func TestAnsweredClaimDoesNotTimeOut(t *testing.T) {
	h := hub.New(nil, hub.WithClaimTimeout(30*time.Millisecond))
	holder, claimant := session(16, nil), session(16, nil)
	claim := claimed(t, h, holder, claimant)
	h.Grant(holder, claim, "box")
	nextFrame(t, claimant)
	time.Sleep(100 * time.Millisecond)
	noFrame(t, claimant)
}

func TestOfferOfAnInviteHeldByAnotherConnectionIsBadFrame(t *testing.T) {
	h := hub.New(nil)
	a, b := session(16, nil), session(16, nil)
	if e := h.Offer(a, inv); e != nil {
		t.Fatal(e)
	}
	wantCode(t, h.Offer(b, inv), proto.CodeBadFrame)
	if e := h.Offer(a, inv); e != nil {
		t.Fatalf("re-offer by the holder: %v", e)
	}
	// The failed offer did not steal anything.
	if e := h.Claim(b, "c1", inv, epk, req); e != nil {
		t.Fatal(e)
	}
	if got := nextFrame(t, a); got["t"] != "claim_request" {
		t.Fatalf("holder received %v", got)
	}
	noFrame(t, b)
}

func TestSeventeenthOfferIsBadFrame(t *testing.T) {
	rec := newRecorder()
	h := hub.New(rec)
	s := session(16, nil)
	for i := range hub.MaxOffers {
		if e := h.Offer(s, inviteID(i)); e != nil {
			t.Fatalf("offer %d: %v", i, e)
		}
	}
	wantCode(t, h.Offer(s, inviteID(99)), proto.CodeBadFrame)
	// Re-offering one already held is not a new offer; withdrawing makes room.
	if e := h.Offer(s, inviteID(0)); e != nil {
		t.Fatal(e)
	}
	h.Withdraw(s, inviteID(0))
	if e := h.Offer(s, inviteID(99)); e != nil {
		t.Fatal(e)
	}
	if rec.offers.Load() != hub.MaxOffers {
		t.Fatalf("offers = %d", rec.offers.Load())
	}
}

func TestWithdrawIsIdempotentAndOnlyConcernsOwnOffers(t *testing.T) {
	rec := newRecorder()
	h := hub.New(rec)
	a, b := session(16, nil), session(16, nil)
	h.Withdraw(a, inv) // nothing offered
	h.Offer(a, inv)
	h.Withdraw(b, inv) // not b's
	if rec.offers.Load() != 1 {
		t.Fatalf("offers = %d, want 1", rec.offers.Load())
	}
	h.Withdraw(a, inv)
	h.Withdraw(a, inv)
	if rec.offers.Load() != 0 {
		t.Fatalf("offers = %d, want 0", rec.offers.Load())
	}
	wantCode(t, h.Claim(b, "c1", inv, epk, req), proto.CodeNoInvite)
}

func TestGrantOfAnUnknownOrForeignClaimIsNoInvite(t *testing.T) {
	h := hub.New(nil)
	holder, claimant, stranger := session(16, nil), session(16, nil), session(16, nil)
	wantCode(t, h.Grant(stranger, "nope", "box"), proto.CodeNoInvite)
	claim := claimed(t, h, holder, claimant)
	wantCode(t, h.Grant(stranger, claim, "box"), proto.CodeNoInvite)
	wantCode(t, h.Grant(claimant, claim, "box"), proto.CodeNoInvite)
	h.RefuseClaim(stranger, claim) // not addressed to stranger: ignored
	noFrame(t, claimant)
	if e := h.Grant(holder, claim, "box"); e != nil { // still pending
		t.Fatal(e)
	}
	if got := nextFrame(t, claimant); got["t"] != "granted" {
		t.Fatalf("claimant received %v", got)
	}
}

func TestSaturatedHolderIsNoInvite(t *testing.T) {
	var killed atomic.Bool
	h := hub.New(nil)
	holder := session(1, &killed)
	h.Offer(holder, inv)
	claimant := session(16, nil)
	if e := h.Claim(claimant, "c1", inv, epk, req); e != nil { // fills the queue
		t.Fatal(e)
	}
	wantCode(t, h.Claim(claimant, "c2", inv, epk, req), proto.CodeNoInvite)
	if !killed.Load() {
		t.Fatal("saturated holder not killed")
	}
}
