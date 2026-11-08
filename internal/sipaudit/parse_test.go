package sipaudit

import (
	"fmt"
	"strings"
	"testing"
)

func TestFraming(t *testing.T) {
	start := "INVITE sip:test@example.test SIP/2.0\r\n"
	for _, tc := range []struct {
		name, text string
		tcp        bool
		want       error
	}{
		{"UDP implicit body", start + "i: id\r\n\r\nbody", false, nil},
		{"TCP missing length", start + "i: id\r\n\r\nbody", true, ErrMalformed},
		{"compact", start + "i: id\r\nl: 4\r\n\r\nbody", true, nil},
		{"truncated", start + "l: 5\r\n\r\nbody", false, ErrIncomplete},
		{"negative", start + "l: -1\r\n\r\n", true, ErrMalformed},
		{"plus sign", start + "l: +1\r\n\r\nx", true, ErrMalformed},
		{"overflow", start + "l: 4294967296\r\n\r\n", true, ErrMalformed},
		{"body limit", start + fmt.Sprintf("l: %d\r\n\r\n", MaxBody+1), true, ErrMalformed},
		{"duplicate same", start + "l: 0\r\nContent-Length: 0\r\n\r\n", true, ErrMalformed},
		{"conflicting", start + "Content-Length: 1\r\nl: 0\r\n\r\nx", false, ErrMalformed},
		{"orphan fold", start + " folded\r\nl: 0\r\n\r\n", true, ErrMalformed},
		{"header limit", start + strings.Repeat("x", MaxHeader), true, ErrMalformed},
		{"response", "SIP/2.0 401 Unauthorized\r\nCSeq: 5\tINVITE\r\nl: 0\r\n\r\n", true, nil},
		{"mismatched CSeq", start + "CSeq: 1 OPTIONS\r\nl: 0\r\n\r\n", true, ErrMalformed},
		{"duplicate CSeq", start + "CSeq: 1 INVITE\r\nCSeq: 2 INVITE\r\nl: 0\r\n\r\n", false, ErrMalformed},
		{"random", "GARBAGE\r\nl: 0\r\n\r\n", false, ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, n, err := Parse([]byte(tc.text), tc.tcp)
			if err != tc.want {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if err == nil && (wire == nil || n != len(tc.text)) {
				t.Fatalf("framing %d/%d", n, len(tc.text))
			}
		})
	}
	wire, _, err := Parse([]byte(start+"f: <sip:a@example.test>\r\n ;tag=one\r\ni: call\r\nc: application/sdp\r\nl: 4\r\n\r\nbody"), true)
	if err != nil {
		t.Fatal(err)
	}
	r := Record(wire, 123)
	if r.CallID != "call" || r.From != "<sip:a@example.test> ;tag=one" || r.ContentType != "application/sdp" || string(r.Body) != "body" {
		t.Fatalf("compact/folded: %v", r)
	}
}

func FuzzSIP(f *testing.F) {
	f.Add([]byte("SIP/2.0 401 Unauthorized\r\nCSeq: 1 INVITE\r\nl: 0\r\n\r\n"), true)
	f.Add([]byte("INVITE sip:a@example.test SIP/2.0\r\nc: application/sdp\r\n\r\nv=0\r\n"), false)
	f.Fuzz(func(t *testing.T, data []byte, tcp bool) {
		wire, n, err := Parse(data, tcp)
		if err == nil {
			if n <= 0 || n > len(data) || len(wire.LayerPayload()) > MaxBody {
				t.Fatal("unbounded frame")
			}
			r := Record(wire, 0)
			Analyze(r)
			parseSDP(r.Body)
		}
	})
}
