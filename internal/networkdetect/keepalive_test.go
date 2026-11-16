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

func TestKeepAliveAfterFINConsumesSequenceSpace(t *testing.T) {
	for _, sequence := range []uint32{100, ^uint32(0) - 3} {
		for _, peerFIN := range []bool{false, true} {
			e, _ := New(DefaultConfig())
			ev := baseEvent("data", 1)
			ev.Seq, ev.Payload = sequence, []byte("abcdefgh")
			e.Observe(ev)
			end := ev
			end.At, end.Kind, end.Payload, end.FIN = end.At+1, "end", nil, true
			end.Seq = sequence + 8
			if peerFIN {
				end.SrcIP, end.DstIP, end.SrcPort, end.DstPort = ev.DstIP, ev.SrcIP, ev.DstPort, ev.SrcPort
			}
			e.Observe(end)
			ev.Seq = sequence + 8
			if peerFIN {
				ev.Seq--
			}
			ev.Payload, ev.KeepAliveEligible = []byte{0}, true
			for range 3 {
				ev.At += 2
				ev.Ack++
				e.Observe(ev)
			}
			if e.Stats().ConflictingOverlaps != 0 {
				t.Fatalf("FIN keepalive treated as overlap: %+v", e.Stats())
			}
		}
	}
}
