package mail

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/decoder/core"
)

func TestNewMailIDOccurrenceIdentity(t *testing.T) {
	conv := &core.ConversationInfo{
		Ident:             "client:1234-server:25",
		FirstClientPacket: time.Unix(1700000000, 123456789),
	}
	buf := []byte("Subject: repeated\r\n\r\nsame body")

	id := newMailID(conv, buf, "SMTP", 0)
	if got := newMailID(conv, buf, "SMTP", 0); got != id {
		t.Fatalf("same occurrence context produced IDs %q and %q", id, got)
	}
	if len(id) != 20 {
		t.Fatalf("ID length = %d, want 20", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("ID %q is not hexadecimal: %v", id, err)
	}

	tests := []struct {
		name    string
		conv    *core.ConversationInfo
		origin  string
		ordinal uint64
	}{
		{
			name:    "different ordinal",
			conv:    conv,
			origin:  "SMTP",
			ordinal: 1,
		},
		{
			name: "different first timestamp",
			conv: &core.ConversationInfo{
				Ident:             conv.Ident,
				FirstClientPacket: conv.FirstClientPacket.Add(time.Nanosecond),
			},
			origin: "SMTP",
		},
		{
			name:    "different origin",
			conv:    conv,
			origin:  "POP3",
			ordinal: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newMailID(tt.conv, buf, tt.origin, tt.ordinal); got == id {
				t.Fatalf("changed occurrence context produced unchanged ID %q", got)
			}
		})
	}
}

func TestNewMailIDUsesUnambiguousFields(t *testing.T) {
	timestamp := time.Unix(1700000000, 0)
	left := &core.ConversationInfo{Ident: "bc", FirstClientPacket: timestamp}
	right := &core.ConversationInfo{Ident: "c", FirstClientPacket: timestamp}

	if leftID, rightID := newMailID(left, []byte("mail"), "a", 0), newMailID(right, []byte("mail"), "ab", 0); leftID == rightID {
		t.Fatalf("ambiguous origin and ident boundaries produced ID %q", leftID)
	}
}
