package hub_test

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scolomer/xs-parley/relay/internal/hub"
	"github.com/scolomer/xs-parley/relay/internal/proto"
)

const xid = "AAAAAAAAAAAAAAAAAAAAAA"

func fp(c byte) string { return "xs:" + strings.Repeat(string(c), 43) }

func session(queue int, killed *atomic.Bool) *hub.Session {
	return hub.NewSession(slog.New(slog.DiscardHandler), queue, func() {
		if killed != nil {
			killed.Store(true)
		}
	})
}

func next(t *testing.T, s *hub.Session) string {
	t.Helper()
	select {
	case f := <-s.Out():
		return string(f)
	default:
		t.Fatal("no frame queued")
		return ""
	}
}

func TestSlowConsumerIsKilledInsteadOfBlockingTheHub(t *testing.T) {
	h := hub.New(nil)
	var killed atomic.Bool
	slow := session(1, &killed)
	fast := session(16, nil)
	h.Join(slow, xid, fp('A'), "boxA")
	h.Join(fast, xid, fp('B'), "boxB") // fills slow's queue with a presence
	if killed.Load() {
		t.Fatal("killed too early")
	}
	if e := h.Route(fast, xid, fp('A'), []byte(`{}`)); e == nil || e.Code != proto.CodeOffline {
		t.Fatalf("route to a saturated connection = %v, want offline", e)
	}
	if !killed.Load() {
		t.Fatal("saturated connection not killed")
	}
}

func TestPresenceIsNotSentToTheJoiningMember(t *testing.T) {
	h := hub.New(nil)
	a, b := session(16, nil), session(16, nil)
	h.Join(a, xid, fp('A'), "boxA")
	h.Join(b, xid, fp('B'), "boxB")
	if got := next(t, a); !strings.Contains(got, `"online":true`) || !strings.Contains(got, fp('B')) {
		t.Fatalf("A received %s", got)
	}
	select {
	case f := <-b.Out():
		t.Fatalf("B received its own presence: %s", f)
	default:
	}
}

func TestJoiningAnotherFingerprintOnTheSameConnectionLeavesTheFirst(t *testing.T) {
	h := hub.New(nil)
	observer, c := session(16, nil), session(16, nil)
	h.Join(observer, xid, fp('A'), "boxA")
	h.Join(c, xid, fp('B'), "box1")
	next(t, observer)
	h.Join(c, xid, fp('C'), "box2")
	if got := next(t, observer); !strings.Contains(got, `"online":false`) || !strings.Contains(got, fp('B')) {
		t.Fatalf("expected offline for the old fingerprint, got %s", got)
	}
	if got := next(t, observer); !strings.Contains(got, `"online":true`) || !strings.Contains(got, fp('C')) {
		t.Fatalf("expected online for the new fingerprint, got %s", got)
	}
	members, _ := h.Members(observer, xid)
	if len(members) != 2 {
		t.Fatalf("members = %v", members)
	}
}

func TestDisconnectIsIdempotentAndLeavesNoState(t *testing.T) {
	h := hub.New(nil)
	a := session(16, nil)
	h.Join(a, xid, fp('A'), "boxA")
	h.Disconnect(a)
	h.Disconnect(a)
	if e := h.Leave(a, xid); e == nil || e.Code != proto.CodeNotJoined {
		t.Fatalf("Leave after Disconnect = %v", e)
	}
	b := session(16, nil)
	h.Join(b, xid, fp('B'), "boxB")
	members, _ := h.Members(b, xid)
	if len(members) != 1 {
		t.Fatalf("members = %v, want only B", members)
	}
}
