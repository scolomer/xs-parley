// Package proto parses and encodes the relay frames of SPEC §6.3.
//
// The relay is blind: the "env" member of a send frame is kept as raw bytes
// and copied verbatim into the deliver frame; it is never decoded.
package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

const (
	// Version is the only protocol version spoken by the relay.
	Version = 1
	// MaxFrame is the largest accepted frame, in bytes (SPEC §6.4).
	MaxFrame = 64 * 1024
)

// Frame types, client to relay.
const (
	TypeJoin  = "join"
	TypeLeave = "leave"
	TypeList  = "list"
	TypeSend  = "send"

	// Invitation frames (SPEC §6.3), which need no join.
	TypeOffer    = "offer"
	TypeWithdraw = "withdraw"
	TypeClaim    = "claim"
	TypeGrant    = "grant"
	TypeRefuse   = "refuse"
)

// Frame types, relay to client.
const (
	TypeOK       = "ok"
	TypeMembers  = "members"
	TypeSent     = "sent"
	TypeError    = "error"
	TypeDeliver  = "deliver"
	TypePresence = "presence"

	TypeGranted      = "granted"
	TypeClaimRequest = "claim_request"
)

// Error codes carried by error frames.
const (
	CodeOffline   = "offline"
	CodeNotJoined = "not_joined"
	CodeReplaced  = "replaced"
	CodeBadFrame  = "bad_frame"
	CodeTooLarge  = "too_large"
	CodeNoInvite  = "no_invite"
	CodeTimeout   = "timeout"
)

// MaxBox is the longest accepted invitation box, in characters.
const MaxBox = 8192

// MaxReq is the longest accepted claim request, in characters.
const MaxReq = 4096

// EPKLen is the length of an ephemeral public key (X25519), in bytes.
const EPKLen = 32

var (
	idRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	xshellIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	fpRe       = regexp.MustCompile(`^xs:[A-Za-z0-9_-]{43}$`)
	certBoxRe  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// invite_id has the same shape as xshell_id; claim has the shape of id.
	inviteIDRe = xshellIDRe
	claimRe    = idRe
)

// Inbound is a validated client-to-relay frame. Only the fields required by
// Type are set.
type Inbound struct {
	Type     string
	ID       string
	XshellID string
	FP       string
	CertBox  string
	To       string
	Env      json.RawMessage
	InviteID string
	Claim    string
	Box      string
	EPK      string
	Req      string
}

// FrameError reports a frame that must be answered with error bad_frame.
// ID is set only when the frame carried a valid id; Type only when the frame
// carried a known type.
type FrameError struct {
	Type    string
	ID      string
	Message string
}

func (e *FrameError) Error() string { return e.Message }

func badFrame(typ, id, format string, args ...any) *FrameError {
	return &FrameError{Type: typ, ID: id, Message: fmt.Sprintf(format, args...)}
}

// Parse decodes and validates one client frame. Unknown members are ignored;
// members are matched case-sensitively and exactly as written.
func Parse(data []byte) (Inbound, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
		return Inbound{}, badFrame("", "", "la trame n'est pas un objet JSON")
	}
	// The id is echoed in the error even when another member is invalid.
	id, _ := stringMember(members, "id")
	if !idRe.MatchString(id) {
		id = ""
	}

	var version int
	if raw, ok := members["v"]; !ok || json.Unmarshal(raw, &version) != nil || version != Version {
		return Inbound{}, badFrame("", id, "version de protocole absente ou non prise en charge (attendu : %d)", Version)
	}
	typ, ok := stringMember(members, "t")
	if !ok {
		return Inbound{}, badFrame("", id, "type de trame absent")
	}

	in := Inbound{Type: typ}
	var needs []string
	switch typ {
	case TypeJoin:
		needs = []string{"id", "xshell_id", "fp", "cert_box"}
	case TypeLeave, TypeList:
		needs = []string{"id", "xshell_id"}
	case TypeSend:
		needs = []string{"id", "xshell_id", "to", "env"}
	case TypeOffer, TypeWithdraw:
		needs = []string{"id", "invite_id"}
	case TypeClaim:
		needs = []string{"id", "invite_id", "epk", "req"}
	case TypeGrant:
		needs = []string{"id", "claim", "box"}
	case TypeRefuse:
		needs = []string{"id", "claim"}
	default:
		return Inbound{}, badFrame("", id, "type de trame inconnu")
	}
	for _, name := range needs {
		if err := in.set(members, name); err != nil {
			return Inbound{}, badFrame(typ, id, "%v", err)
		}
	}
	return in, nil
}

func stringMember(members map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := members[name]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func (in *Inbound) set(members map[string]json.RawMessage, name string) error {
	if name == "env" {
		raw, ok := members[name]
		if !ok || len(raw) == 0 || raw[0] != '{' {
			return fmt.Errorf("env doit être un objet JSON")
		}
		in.Env = raw
		return nil
	}
	value, ok := stringMember(members, name)
	if !ok {
		return fmt.Errorf("%s absent ou n'est pas une chaîne", name)
	}
	var valid bool
	var dst *string
	switch name {
	case "id":
		valid, dst = idRe.MatchString(value), &in.ID
	case "xshell_id":
		valid, dst = xshellIDRe.MatchString(value), &in.XshellID
	case "fp", "to":
		valid = fpRe.MatchString(value)
		dst = &in.FP
		if name == "to" {
			dst = &in.To
		}
	case "cert_box":
		valid, dst = certBoxRe.MatchString(value), &in.CertBox
	case "invite_id":
		valid, dst = inviteIDRe.MatchString(value), &in.InviteID
	case "claim":
		valid, dst = claimRe.MatchString(value), &in.Claim
	case "box":
		// Not a {1,8192} repetition: RE2 caps repeat counts at 1000.
		valid, dst = len(value) <= MaxBox && certBoxRe.MatchString(value), &in.Box
	case "epk":
		// Strict: the unused trailing bits of the last character must be zero,
		// so that exactly one 43-character string encodes a given key.
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
		valid, dst = err == nil && len(raw) == EPKLen, &in.EPK
	case "req":
		valid, dst = len(value) <= MaxReq && certBoxRe.MatchString(value), &in.Req
	}
	if !valid {
		return fmt.Errorf("%s invalide", name)
	}
	*dst = value
	return nil
}

// Member is one entry of a members frame.
type Member struct {
	FP      string `json:"fp"`
	CertBox string `json:"cert_box"`
}

type header struct {
	V int    `json:"v"`
	T string `json:"t"`
}

func marshal(v any) []byte {
	// Frames contain only strings, booleans and slices of them: Marshal cannot fail.
	out, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("proto: marshal frame: %v", err))
	}
	return out
}

// OK encodes the ok response.
func OK(id string) []byte {
	return marshal(struct {
		header
		ID string `json:"id"`
	}{header{Version, TypeOK}, id})
}

// Sent encodes the sent response.
func Sent(id string) []byte {
	return marshal(struct {
		header
		ID string `json:"id"`
	}{header{Version, TypeSent}, id})
}

// MembersFrame encodes the members response.
func MembersFrame(id, xshellID string, members []Member) []byte {
	if members == nil {
		members = []Member{}
	}
	return marshal(struct {
		header
		ID       string   `json:"id"`
		XshellID string   `json:"xshell_id"`
		Members  []Member `json:"members"`
	}{header{Version, TypeMembers}, id, xshellID, members})
}

// Error encodes an error frame; id and xshellID are omitted when empty.
func Error(code, id, xshellID, message string) []byte {
	return marshal(struct {
		header
		ID       string `json:"id,omitempty"`
		Code     string `json:"code"`
		XshellID string `json:"xshell_id,omitempty"`
		Message  string `json:"message"`
	}{header{Version, TypeError}, id, code, xshellID, message})
}

// Presence encodes a presence push; certBox is omitted when empty (offline).
func Presence(xshellID, fp string, online bool, certBox string) []byte {
	return marshal(struct {
		header
		XshellID string `json:"xshell_id"`
		FP       string `json:"fp"`
		Online   bool   `json:"online"`
		CertBox  string `json:"cert_box,omitempty"`
	}{header{Version, TypePresence}, xshellID, fp, online, certBox})
}

// Deliver encodes a deliver push around env, copied byte for byte: going
// through json.Marshal would compact it and escape <, > and &. xshellID is
// validated by Parse and needs no escaping.
func Deliver(xshellID string, env []byte) []byte {
	var b bytes.Buffer
	b.Grow(len(env) + 80)
	b.WriteString(`{"v":1,"t":"deliver","xshell_id":"`)
	b.WriteString(xshellID)
	b.WriteString(`","env":`)
	b.Write(env)
	b.WriteByte('}')
	return b.Bytes()
}

// Granted encodes the response to a claim: the box is relayed as received.
func Granted(id, box string) []byte {
	return marshal(struct {
		header
		ID  string `json:"id"`
		Box string `json:"box"`
	}{header{Version, TypeGranted}, id, box})
}

// ClaimRequest encodes the push telling an offer holder that someone claims
// its invitation. epk and req are the claimant's, relayed as received.
func ClaimRequest(inviteID, claim, epk, req string) []byte {
	return marshal(struct {
		header
		InviteID string `json:"invite_id"`
		Claim    string `json:"claim"`
		EPK      string `json:"epk"`
		Req      string `json:"req"`
	}{header{Version, TypeClaimRequest}, inviteID, claim, epk, req})
}
