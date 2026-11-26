package modbus

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestDeviceIdentityRequiresMatchedContinuation(t *testing.T) {
	for _, tc := range []struct {
		name            string
		object, replyID byte
		want            bool
	}{
		{"matched", 2, 12, true}, {"different transaction", 2, 13, false}, {"different starting object", 1, 12, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reader(t)
			r.conversation.TCPHandshakeComplete = true
			r.conversation.Data = core.DataFragments{
				fragment(wire(11, 43, 14, 1, 0), 100, false),
				fragment(wire(11, 43, 14, 1, 1, 255, 2, 1, 0, 1, 'A'), 200, true),
				fragment(wire(12, 43, 14, 1, tc.object), 300, false),
				fragment(wire(tc.replyID, 43, 14, 1, 1, 0, 0, 1, 2, 1, 'B'), 400, true),
			}
			rows := records(r)
			if len(rows) != 4 || len(rows[1].DeviceIdentity) != 0 {
				t.Fatalf("unexpected page records: %v", rows)
			}
			id := rows[3].DeviceIdentity
			if !tc.want {
				if len(id) != 0 {
					t.Fatalf("assembled unrelated pages: %v", id)
				}
				return
			}
			if len(id) != 2 || id[0].ID != 0 || string(id[0].Value) != "A" || id[1].ID != 2 || string(id[1].Value) != "B" || len(rows[3].DeviceIDObjects) != 1 {
				t.Fatalf("wire and joined identities: %v", rows[3])
			}
		})
	}
}
