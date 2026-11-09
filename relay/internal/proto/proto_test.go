package proto_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scolomer/omp-xshell/relay/internal/proto"
)

const (
	invite = "AAAAAAAAAAAAAAAAAAAAAA"
	// epkOK is a canonical base64url encoding of 32 bytes.
	epkOK = "Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Ab_-Abw"
)

func frame(t string, members map[string]any) []byte {
	f := map[string]any{"v": 1, "t": t}
	for k, v := range members {
		f[k] = v
	}
	data, _ := json.Marshal(f)
	return data
}

func claimFrame(id, inviteID, epk, req string) []byte {
	return frame("claim", map[string]any{"id": id, "invite_id": inviteID, "epk": epk, "req": req})
}

func TestParseInviteFrames(t *testing.T) {
	reqMax := strings.Repeat("r", proto.MaxReq)
	box := strings.Repeat("b", proto.MaxBox)
	tests := []struct {
		name string
		data []byte
		want proto.Inbound
	}{
		{"offer", frame("offer", map[string]any{"id": "o1", "invite_id": invite}),
			proto.Inbound{Type: "offer", ID: "o1", InviteID: invite}},
		{"withdraw", frame("withdraw", map[string]any{"id": "w1", "invite_id": invite}),
			proto.Inbound{Type: "withdraw", ID: "w1", InviteID: invite}},
		{"claim", claimFrame("c1", invite, epkOK, reqMax),
			proto.Inbound{Type: "claim", ID: "c1", InviteID: invite, EPK: epkOK, Req: reqMax}},
		{"grant", frame("grant", map[string]any{"id": "g1", "claim": "cl_-9", "box": box}),
			proto.Inbound{Type: "grant", ID: "g1", Claim: "cl_-9", Box: box}},
		{"refuse", frame("refuse", map[string]any{"id": "r1", "claim": strings.Repeat("c", 64)}),
			proto.Inbound{Type: "refuse", ID: "r1", Claim: strings.Repeat("c", 64)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := proto.Parse(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != tc.want.Type || got.ID != tc.want.ID || got.InviteID != tc.want.InviteID ||
				got.Claim != tc.want.Claim || got.Box != tc.want.Box || got.EPK != tc.want.EPK || got.Req != tc.want.Req {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseRejectsInvalidInviteFields(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"offer without invite_id", frame("offer", map[string]any{"id": "o"})},
		{"invite_id short", frame("offer", map[string]any{"id": "o", "invite_id": "short"})},
		{"invite_id long", claimFrame("o", invite+"A", epkOK, "r")},
		{"invite_id alphabet", frame("withdraw", map[string]any{"id": "o", "invite_id": strings.Repeat("+", 22)})},
		{"invite_id not a string", frame("offer", map[string]any{"id": "o", "invite_id": 7})},
		{"claim without id", frame("claim", map[string]any{"invite_id": invite, "epk": epkOK, "req": "r"})},
		{"claim without epk", frame("claim", map[string]any{"id": "c", "invite_id": invite, "req": "r"})},
		{"claim without req", frame("claim", map[string]any{"id": "c", "invite_id": invite, "epk": epkOK})},
		{"claim epk 42 chars", claimFrame("c", invite, epkOK[:42], "r")},
		{"claim epk 44 chars", claimFrame("c", invite, epkOK+"A", "r")},
		{"claim epk with padding", claimFrame("c", invite, epkOK+"=", "r")},
		{"claim epk alphabet", claimFrame("c", invite, strings.Repeat("+", 43), "r")},
		{"claim epk non-canonical tail", claimFrame("c", invite, strings.Repeat("A", 42)+"B", "r")},
		{"claim epk not a string", frame("claim", map[string]any{"id": "c", "invite_id": invite, "epk": 7, "req": "r"})},
		{"claim empty req", claimFrame("c", invite, epkOK, "")},
		{"claim req too long", claimFrame("c", invite, epkOK, strings.Repeat("r", proto.MaxReq+1))},
		{"claim req alphabet", claimFrame("c", invite, epkOK, "a+b=")},
		{"claim req not a string", frame("claim", map[string]any{"id": "c", "invite_id": invite, "epk": epkOK, "req": []int{1}})},
		{"grant without claim", frame("grant", map[string]any{"id": "g", "box": "b"})},
		{"grant empty claim", frame("grant", map[string]any{"id": "g", "claim": "", "box": "b"})},
		{"grant claim too long", frame("grant", map[string]any{"id": "g", "claim": strings.Repeat("c", 65), "box": "b"})},
		{"grant claim alphabet", frame("grant", map[string]any{"id": "g", "claim": "a b", "box": "b"})},
		{"grant without box", frame("grant", map[string]any{"id": "g", "claim": "c"})},
		{"grant empty box", frame("grant", map[string]any{"id": "g", "claim": "c", "box": ""})},
		{"grant box alphabet", frame("grant", map[string]any{"id": "g", "claim": "c", "box": "a+b="})},
		{"grant box too long", frame("grant", map[string]any{"id": "g", "claim": "c", "box": strings.Repeat("b", proto.MaxBox+1)})},
		{"grant box not a string", frame("grant", map[string]any{"id": "g", "claim": "c", "box": map[string]any{}})},
		{"refuse without claim", frame("refuse", map[string]any{"id": "r"})},
		{"refuse claim alphabet", frame("refuse", map[string]any{"id": "r", "claim": "a/b"})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := proto.Parse(tc.data)
			fe, ok := err.(*proto.FrameError)
			if !ok {
				t.Fatalf("err = %v, want a FrameError", err)
			}
			if fe.Type == "" {
				t.Fatalf("error lost the frame type: %+v", fe)
			}
		})
	}
}

func TestServerFramesEncoding(t *testing.T) {
	if got, want := string(proto.Granted("c1", "bx")), `{"v":1,"t":"granted","id":"c1","box":"bx"}`; got != want {
		t.Fatalf("Granted = %s", got)
	}
	epk, req := strings.Repeat("A", 42)+"w", "Qr_-9"
	if got, want := string(proto.ClaimRequest(invite, "cl", epk, req)), `{"v":1,"t":"claim_request","invite_id":"`+invite+`","claim":"cl","epk":"`+epk+`","req":"`+req+`"}`; got != want {
		t.Fatalf("ClaimRequest = %s", got)
	}
}
