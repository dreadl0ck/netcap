package reassembly

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestIdleExpiryUsesBothDirectionsAndStrictCaptureCutoff(t *testing.T) {
	for _, retain := range []bool{false, true} {
		factory := &dueFactory{streams: make(map[key][]*dueRecorder), retain: retain}
		pool := NewStreamPoolWithIdleExpiry(factory)
		a := NewAssembler(pool)
		flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
		feed := func(net gopacket.Flow, seen int64, sequence uint32, syn bool, payload string) {
			ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Unix(seen, 0)})
			a.AssembleWithContext(net, &layers.TCP{SrcPort: 1000, DstPort: 2000, SYN: syn, Seq: sequence,
				BaseLayer: layers.BaseLayer{Payload: []byte(payload)}}, &ctx)
		}
		feed(flow, 100, 1, true, "")
		feed(flow, 101, 10, false, "pending")
		feed(flow.Reverse(), 200, 1, true, "")
		if len(pool.idleDue) != 1 {
			t.Fatal("open connection missing idle index")
		}
		a.FlushWithOptions(FlushOptions{TI: time.Unix(150, 0)})
		if len(pool.connections(nil)) != 1 {
			t.Fatal("recent opposite direction expired")
		}
		a.FlushWithOptions(FlushOptions{TI: time.Unix(200, 0)})
		if len(pool.connections(nil)) != 1 {
			t.Fatal("strict idle cutoff expired equal timestamp")
		}
		// Pending and idle deadlines overlap but must claim a connection only once.
		a.FlushWithOptions(FlushOptions{T: time.Unix(202, 0), TI: time.Unix(201, 0)})
		completed := 0
		for _, streams := range factory.streams {
			for _, stream := range streams {
				for _, event := range stream.events {
					if event.Kind == "complete" {
						completed++
					}
				}
			}
		}
		if completed != 1 || len(pool.idleDue) != 0 || len(pool.pendingDue) != 0 {
			t.Fatalf("retained=%v: completions=%d pending=%d idle=%d", retain, completed, len(pool.pendingDue), len(pool.idleDue))
		}
		a.FlushWithOptions(FlushOptions{TC: time.Unix(201, 0)})
		if len(pool.connections(nil)) != 0 {
			t.Fatal("retained closed connection not reclaimed")
		}
	}
}
