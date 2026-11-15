package networkdetect

import "testing"

func TestKeepAliveDoesNotBecomeInjection(t *testing.T) {
	for _, sequence := range []uint32{100, ^uint32(0) - 3} {
		for _, tc := range []struct {
			name             string
			eligible, closed bool
			size             int
			delta            uint32
			conflict         bool
		}{
			{"keepalive", true, false, 1, 1, false},
			{"not-ack", false, false, 1, 1, true},
			{"older-conflict", true, false, 1, 2, true},
			{"two-byte-conflict", true, false, 2, 2, true},
			{"closed", true, true, 1, 1, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e, _ := New(DefaultConfig())
				ev := baseEvent("data", 1)
				ev.Seq, ev.Payload = sequence, []byte("abcdefgh")
				if _, err := e.Observe(ev); err != nil {
					t.Fatal(err)
				}
				if tc.closed {
					end := ev
					end.At++
					end.Kind = "end"
					end.Payload = nil
					e.Observe(end)
				}
				ev.At += 2
				ev.Seq = sequence + 8 - tc.delta
				ev.Payload = make([]byte, tc.size)
				ev.KeepAliveEligible = tc.eligible
				if _, err := e.Observe(ev); err != nil {
					t.Fatal(err)
				}
				var conflicts int
				for _, alert := range e.Flush() {
					if alert.Name == "tcp.overlap-conflict" {
						conflicts++
					}
				}
				if (conflicts > 0) != tc.conflict || (e.Stats().ConflictingOverlaps > 0) != tc.conflict {
					t.Fatalf("alerts=%d stats=%+v", conflicts, e.Stats())
				}
			})
		}
	}
}
