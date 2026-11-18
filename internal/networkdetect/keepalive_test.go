package networkdetect

import (
	"strings"
	"testing"
)

func TestStaleProbeQualificationPreservesConflict(t *testing.T) {
	for _, tc := range []struct {
		name             string
		seq              uint32
		payload          []byte
		ack, reset, gap, want bool
	}{
		{"previous-end", 3, []byte{0}, true, false, false, true},
		{"second-end", 7, []byte{0}, true, false, false, true},
		{"interior-byte", 2, []byte{0}, true, false, false, false},
		{"nonzero", 3, []byte{1}, true, false, false, false},
		{"no-ack", 3, []byte{0}, false, false, false, false},
		{"multiple-bytes", 3, []byte{0, 0}, true, false, false, false},
		{"reset", 3, []byte{0}, true, true, false, false},
		{"capture-gap", 3, []byte{0}, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := New(DefaultConfig())
			start := ^uint32(0) - 3
			ev := baseEvent("data", 1)
			ev.Seq, ev.Payload = start, []byte("abcd")
			e.Observe(ev)
			d := e.flows[flowKey(ev)].directions[endpoint(ev.SrcIP, ev.SrcPort)]
			if d.prefixEnds != nil {
				t.Fatal("one observed end allocated a bitmap")
			}
			ev.At++
			ev.Seq, ev.Payload = start+4, []byte("efgh")
			e.Observe(ev)
			ev.At++
			ev.Seq, ev.Payload = start+8, []byte("ijkl")
			e.Observe(ev)
			if tc.gap {
				ev.At++
				ev.Seq, ev.Payload = start+13, []byte("tail")
				if _, err := e.Observe(ev); err != nil || e.Stats().StreamGaps != 1 {
					t.Fatalf("capture gap not recorded: %v, %+v", err, e.Stats())
				}
			}
			if tc.reset {
				end := ev
				end.Kind, end.Payload = "end", nil
				e.Observe(end)
			}
			if (d.prefixEnds == nil) != (tc.gap || tc.reset) {
				t.Fatal("unexpected bitmap retention after multiple observed ends")
			}
			ev.At++
			ev.Seq, ev.Payload, ev.KeepAliveEligible = start+tc.seq, tc.payload, tc.ack
			alerts, err := e.Observe(ev)
			if err != nil {
				t.Fatal(err)
			}
			alerts = append(alerts, e.Flush()...)
			if len(alerts) != 1 || alerts[0].Name != "tcp.overlap-conflict" || alerts[0].Severity != "medium" || (e.Stats().StaleProbeCandidates == 1) != tc.want || e.Stats().ConflictingOverlapBytes != uint64(len(tc.payload)) {
				t.Fatalf("alerts=%v stats=%+v", alerts, e.Stats())
			}
			if strings.Contains(strings.Join(alerts[0].Examples, " "), "Possible stale probe") != tc.want {
				t.Fatalf("unexpected evidence: %v", alerts[0].Examples)
			}
		})
	}
}

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
