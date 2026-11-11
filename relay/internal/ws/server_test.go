package ws_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/scolomer/xs-parley/relay/internal/hub"
	"github.com/scolomer/xs-parley/relay/internal/metrics"
	"github.com/scolomer/xs-parley/relay/internal/ws"
)

const (
	xid1 = "AAAAAAAAAAAAAAAAAAAAAA"
	xid2 = "BBBBBBBBBBBBBBBBBBBBBB"
)

func fp(c byte) string { return "xs:" + strings.Repeat(string(c), 43) }

var (
	fpA = fp('A')
	fpB = fp('B')
	fpC = fp('C')
)

type relay struct {
	URL     string
	Metrics *metrics.Metrics
}

func newRelay(t *testing.T) *relay {
	t.Helper()
	return newRelayWith(t)
}

func newRelayWith(t *testing.T, hubOpts ...hub.Option) *relay {
	t.Helper()
	m := metrics.New()
	srv := ws.New(ws.Config{
		Hub: hub.New(m, hubOpts...), Metrics: m, Log: slog.New(slog.DiscardHandler),
		PingInterval: 50 * time.Millisecond,
	})
	mux := http.NewServeMux()
	mux.Handle("/ws", srv)
	ts := httptest.NewServer(mux)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		ts.Close()
	})
	return &relay{URL: "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws", Metrics: m}
}

type client struct {
	t  *testing.T
	ws *websocket.Conn
}

func (r *relay) dial(t *testing.T) *client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, r.URL, nil)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial: %v (HTTP %d)", err, status)
	}
	c.SetReadLimit(1 << 20)
	t.Cleanup(func() { _ = c.CloseNow() })
	return &client{t: t, ws: c}
}

func (c *client) sendRaw(data string) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.ws.Write(ctx, websocket.MessageText, []byte(data)); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *client) send(frame map[string]any) {
	c.t.Helper()
	data, err := json.Marshal(frame)
	if err != nil {
		c.t.Fatal(err)
	}
	c.sendRaw(string(data))
}

func (c *client) recvRaw() []byte {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := c.ws.Read(ctx)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return data
}

type frame map[string]any

func (c *client) recv() frame {
	c.t.Helper()
	raw := c.recvRaw()
	var f frame
	if err := json.Unmarshal(raw, &f); err != nil {
		c.t.Fatalf("frame %q: %v", raw, err)
	}
	return f
}

// expect reads the next frame and checks the given members.
func (c *client) expect(want frame) frame {
	c.t.Helper()
	got := c.recv()
	for k, v := range want {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			c.t.Fatalf("frame %v: %s = %v, want %v", got, k, got[k], v)
		}
	}
	return got
}

func (c *client) join(parleyID, fingerprint, box string) {
	c.t.Helper()
	c.send(frame{"v": 1, "t": "join", "id": "j", "parley_id": parleyID, "fp": fingerprint, "cert_box": box})
	c.expect(frame{"t": "ok", "id": "j"})
}

// probe checks that no frame is pending: the answer to a list on a joined
// parley comes next, after everything queued before it.
func (c *client) probe(parleyID string) frame {
	c.t.Helper()
	c.send(frame{"v": 1, "t": "list", "id": "probe", "parley_id": parleyID})
	return c.expect(frame{"t": "members", "id": "probe"})
}

func (c *client) expectClosed() websocket.StatusCode {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, _, err := c.ws.Read(ctx)
		if err == nil {
			continue
		}
		if status := websocket.CloseStatus(err); status != -1 {
			return status
		}
		c.t.Fatalf("expected a close frame, got %v", err)
	}
}

func sendFrame(id, parleyID, to, env string) string {
	return fmt.Sprintf(`{"v":1,"t":"send","id":%q,"parley_id":%q,"to":%q,"env":%s}`, id, parleyID, to, env)
}

// --- hub semantics over the wire -------------------------------------------

func TestRoutingDeliversEnvelopeByteForByte(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.join(xid1, fpA, "boxA")
	b.join(xid1, fpB, "boxB")
	a.expect(frame{"t": "presence", "parley_id": xid1, "fp": fpB, "online": true, "cert_box": "boxB"})

	// Whitespace, key order, <>&, escapes, number forms and an unknown member
	// must all survive untouched.
	env := `{ "h":{"b":1,"a":"<&>"},  "enc":"x\u00e9\/y", "n":1.0e2,"big":12345678901234567890 ,"sig":null }`
	a.sendRaw(sendFrame("s1", xid1, fpB, env))
	a.expect(frame{"t": "sent", "id": "s1"})

	want := `{"v":1,"t":"deliver","parley_id":"` + xid1 + `","env":` + env + `}`
	if got := string(b.recvRaw()); got != want {
		t.Fatalf("deliver =\n%s\nwant\n%s", got, want)
	}
}

func TestSendToSelfAndMaximumFrameSize(t *testing.T) {
	r := newRelay(t)
	a := r.dial(t)
	a.join(xid1, fpA, "boxA")

	head := sendFrame("s1", xid1, fpA, `{"p":""}`)
	padding := strings.Repeat("x", 64*1024-len(head))
	raw := sendFrame("s1", xid1, fpA, `{"p":"`+padding+`"}`)
	if len(raw) != 64*1024 {
		t.Fatalf("test frame is %d bytes", len(raw))
	}
	a.sendRaw(raw)
	a.expect(frame{"t": "deliver"}) // queued before the sent reply
	a.expect(frame{"t": "sent", "id": "s1"})
}

func TestOfflineAndDisconnectPresence(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.join(xid1, fpA, "boxA")
	b.join(xid1, fpB, "boxB")
	a.expect(frame{"t": "presence", "fp": fpB, "online": true})

	// A fingerprint that never joined.
	a.sendRaw(sendFrame("s1", xid1, fpC, `{}`))
	a.expect(frame{"t": "error", "id": "s1", "code": "offline"})

	// A fingerprint joined on another parley only.
	other := r.dial(t)
	other.join(xid2, fpC, "boxC")
	a.sendRaw(sendFrame("s2", xid1, fpC, `{}`))
	a.expect(frame{"t": "error", "id": "s2", "code": "offline"})

	_ = b.ws.CloseNow()
	pres := a.expect(frame{"t": "presence", "parley_id": xid1, "fp": fpB, "online": false})
	if _, has := pres["cert_box"]; has {
		t.Fatalf("offline presence carries a cert_box: %v", pres)
	}
	a.sendRaw(sendFrame("s3", xid1, fpB, `{}`))
	a.expect(frame{"t": "error", "id": "s3", "code": "offline"})
}

func TestDisconnectAnnouncesOfflineOnEveryParley(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.join(xid1, fpA, "boxA")
	a2 := r.dial(t)
	a2.join(xid2, fpC, "boxC")
	b.join(xid1, fpB, "boxB")
	b.join(xid2, fpB, "boxB")
	a.expect(frame{"t": "presence", "fp": fpB, "online": true})
	a2.expect(frame{"t": "presence", "fp": fpB, "online": true})

	_ = b.ws.CloseNow()
	a.expect(frame{"t": "presence", "parley_id": xid1, "fp": fpB, "online": false})
	a2.expect(frame{"t": "presence", "parley_id": xid2, "fp": fpB, "online": false})
}

func TestLeaveAndList(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.join(xid1, fpA, "boxA")
	b.join(xid1, fpB, "boxB")
	a.expect(frame{"t": "presence", "fp": fpB, "online": true})

	list := a.probe(xid1)
	members := list["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members = %v, want both, the requester included", members)
	}
	first := members[0].(map[string]any)
	if first["fp"] != fpA || first["cert_box"] != "boxA" || list["parley_id"] != xid1 {
		t.Fatalf("members = %v", list)
	}

	b.send(frame{"v": 1, "t": "leave", "id": "l1", "parley_id": xid1})
	b.expect(frame{"t": "ok", "id": "l1"})
	a.expect(frame{"t": "presence", "fp": fpB, "online": false})
	b.send(frame{"v": 1, "t": "list", "id": "q1", "parley_id": xid1})
	b.expect(frame{"t": "error", "id": "q1", "code": "not_joined"})

	// Leaving did not disconnect: B can join again.
	b.join(xid1, fpB, "boxB2")
	a.expect(frame{"t": "presence", "fp": fpB, "online": true, "cert_box": "boxB2"})
}

func TestJoinReplacesAnotherConnection(t *testing.T) {
	r := newRelay(t)
	observer, first := r.dial(t), r.dial(t)
	observer.join(xid1, fpA, "boxA")
	first.join(xid1, fpB, "box1")
	observer.expect(frame{"t": "presence", "fp": fpB, "online": true, "cert_box": "box1"})

	second := r.dial(t)
	second.join(xid1, fpB, "box2")
	replaced := first.expect(frame{"t": "error", "code": "replaced", "parley_id": xid1})
	if _, has := replaced["id"]; has {
		t.Fatalf("replaced carries an id: %v", replaced)
	}
	observer.expect(frame{"t": "presence", "fp": fpB, "online": true, "cert_box": "box2"})

	// The replaced connection is no longer a member...
	first.send(frame{"v": 1, "t": "list", "id": "q", "parley_id": xid1})
	first.expect(frame{"t": "error", "id": "q", "code": "not_joined"})
	// ...and its departure does not take the fingerprint offline.
	_ = first.ws.CloseNow()
	observer.sendRaw(sendFrame("s1", xid1, fpB, `{"to":"second"}`))
	observer.expect(frame{"t": "sent", "id": "s1"})
	second.expect(frame{"t": "deliver"})
	observer.probe(xid1) // no offline presence is pending
}

func TestRejoinOnSameConnectionUpdatesCertBox(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.join(xid1, fpA, "boxA")
	b.join(xid1, fpB, "box1")
	a.expect(frame{"t": "presence", "fp": fpB, "online": true, "cert_box": "box1"})

	b.join(xid1, fpB, "box2") // ok, not an error: no replaced
	a.expect(frame{"t": "presence", "fp": fpB, "online": true, "cert_box": "box2"})

	members := b.probe(xid1)["members"].([]any)
	if len(members) != 2 || members[1].(map[string]any)["cert_box"] != "box2" {
		t.Fatalf("members = %v", members)
	}
	b.probe(xid1) // nothing else was queued for B (no replaced)
}

func TestNotJoined(t *testing.T) {
	r := newRelay(t)
	c := r.dial(t)
	c.send(frame{"v": 1, "t": "list", "id": "q1", "parley_id": xid1})
	c.expect(frame{"t": "error", "id": "q1", "code": "not_joined"})
	c.send(frame{"v": 1, "t": "leave", "id": "l1", "parley_id": xid1})
	c.expect(frame{"t": "error", "id": "l1", "code": "not_joined"})
	c.sendRaw(sendFrame("s1", xid1, fpA, `{}`))
	c.expect(frame{"t": "error", "id": "s1", "code": "not_joined"})

	// Joined on xid1 is not joined on xid2.
	c.join(xid1, fpA, "boxA")
	c.sendRaw(sendFrame("s2", xid2, fpA, `{}`))
	c.expect(frame{"t": "error", "id": "s2", "code": "not_joined"})

	// Another member's fingerprint is no entitlement either.
	other := r.dial(t)
	other.join(xid2, fpB, "boxB")
	c.sendRaw(sendFrame("s3", xid2, fpB, `{}`))
	c.expect(frame{"t": "error", "id": "s3", "code": "not_joined"})
}

func TestConcurrentSendsAreCorrelatedById(t *testing.T) {
	r := newRelay(t)
	a, b := r.dial(t), r.dial(t)
	a.join(xid1, fpA, "boxA")
	b.join(xid1, fpB, "boxB")
	a.expect(frame{"t": "presence", "fp": fpB, "online": true})

	const n = 60
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			to := fpB
			if i%3 == 0 {
				to = fpC // offline
			}
			a.sendRaw(sendFrame(fmt.Sprintf("s%d", i), xid1, to, fmt.Sprintf(`{"i":%d}`, i)))
		}()
	}
	wg.Wait()

	replies := map[string]frame{}
	for range n {
		f := a.recv()
		replies[f["id"].(string)] = f
	}
	for i := range n {
		f := replies[fmt.Sprintf("s%d", i)]
		switch {
		case f == nil:
			t.Fatalf("no reply for s%d", i)
		case i%3 == 0 && (f["t"] != "error" || f["code"] != "offline"):
			t.Fatalf("s%d = %v, want error offline", i, f)
		case i%3 != 0 && f["t"] != "sent":
			t.Fatalf("s%d = %v, want sent", i, f)
		}
	}

	got := map[int]bool{}
	for range n - n/3 {
		env := b.recv()["env"].(map[string]any)
		got[int(env["i"].(float64))] = true
	}
	if len(got) != n-n/3 {
		t.Fatalf("B received %d distinct envelopes, want %d", len(got), n-n/3)
	}
}

// --- frame validation -------------------------------------------------------

func TestTooLarge(t *testing.T) {
	r := newRelay(t)
	c := r.dial(t)
	c.join(xid1, fpA, "boxA")

	c.sendRaw(sendFrame("s1", xid1, fpA, `{"p":"`+strings.Repeat("x", 64*1024)+`"}`))
	c.expect(frame{"t": "error", "code": "too_large"})
	if status := c.expectClosed(); status != websocket.StatusMessageTooBig {
		t.Fatalf("close status = %d, want %d", status, websocket.StatusMessageTooBig)
	}
}

func TestBadFrames(t *testing.T) {
	r := newRelay(t)
	c := r.dial(t)
	c.join(xid1, fpA, "boxA")

	valid := func(mutate func(frame)) string {
		f := frame{"v": 1, "t": "join", "id": "j9", "parley_id": xid2, "fp": fpA, "cert_box": "box"}
		mutate(f)
		data, _ := json.Marshal(f)
		return string(data)
	}
	tests := []struct {
		name, raw, wantID string
	}{
		{"not json", `hello`, ""},
		{"json array", `[1]`, ""},
		{"json null", `null`, ""},
		{"json string", `"join"`, ""},
		{"missing version", `{"t":"list","id":"q","parley_id":"` + xid1 + `"}`, "q"},
		{"version 2", `{"v":2,"t":"list","id":"q","parley_id":"` + xid1 + `"}`, "q"},
		{"version as string", `{"v":"1","t":"list","id":"q","parley_id":"` + xid1 + `"}`, "q"},
		{"missing type", `{"v":1,"id":"q"}`, "q"},
		{"type as number", `{"v":1,"t":1,"id":"q"}`, "q"},
		{"unknown type", `{"v":1,"t":"ping","id":"q"}`, "q"},
		{"server type from client", `{"v":1,"t":"deliver","id":"q"}`, "q"},
		{"case-mismatched type member", `{"v":1,"T":"list","id":"q"}`, "q"},
		{"join without id", valid(func(f frame) { delete(f, "id") }), ""},
		{"invalid id", valid(func(f frame) { f["id"] = "has space" }), ""},
		{"id too long", valid(func(f frame) { f["id"] = strings.Repeat("a", 65) }), ""},
		{"id not a string", valid(func(f frame) { f["id"] = 7 }), ""},
		{"short parley_id", valid(func(f frame) { f["parley_id"] = "short" }), "j9"},
		{"parley_id alphabet", valid(func(f frame) { f["parley_id"] = strings.Repeat("+", 22) }), "j9"},
		{"fp without prefix", valid(func(f frame) { f["fp"] = strings.Repeat("A", 46) }), "j9"},
		{"fp too short", valid(func(f frame) { f["fp"] = "xs:AAAA" }), "j9"},
		{"fp padded", valid(func(f frame) { f["fp"] = fpA + "=" }), "j9"},
		{"missing cert_box", valid(func(f frame) { delete(f, "cert_box") }), "j9"},
		{"empty cert_box", valid(func(f frame) { f["cert_box"] = "" }), "j9"},
		{"cert_box not base64url", valid(func(f frame) { f["cert_box"] = "a+b/c=" }), "j9"},
		{"send without env", `{"v":1,"t":"send","id":"s","parley_id":"` + xid1 + `","to":"` + fpA + `"}`, "s"},
		{"send env not an object", sendFrame("s", xid1, fpA, `"text"`), "s"},
		{"send env null", sendFrame("s", xid1, fpA, `null`), "s"},
		{"send env array", sendFrame("s", xid1, fpA, `[]`), "s"},
		{"send invalid to", `{"v":1,"t":"send","id":"s","parley_id":"` + xid1 + `","to":"nope","env":{}}`, "s"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c.sendRaw(tc.raw)
			got := c.expect(frame{"t": "error", "code": "bad_frame"})
			id, _ := got["id"].(string)
			if id != tc.wantID {
				t.Fatalf("error id = %q, want %q (%v)", id, tc.wantID, got)
			}
			if msg, _ := got["message"].(string); msg == "" {
				t.Fatalf("no message: %v", got)
			}
		})
	}

	t.Run("binary message", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.ws.Write(ctx, websocket.MessageBinary, []byte(`{"v":1,"t":"list"}`)); err != nil {
			t.Fatal(err)
		}
		c.expect(frame{"t": "error", "code": "bad_frame"})
	})

	t.Run("unknown members are ignored", func(t *testing.T) {
		c.sendRaw(`{"v":1,"t":"list","id":"q","parley_id":"` + xid1 + `","extra":{"a":[1]},"future":true}`)
		c.expect(frame{"t": "members", "id": "q"})
	})

	t.Run("the connection survives", func(t *testing.T) {
		c.probe(xid1)
	})
}
