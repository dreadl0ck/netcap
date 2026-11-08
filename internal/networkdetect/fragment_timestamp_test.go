package networkdetect

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
)

func TestFragmentCompletionEventTime(t *testing.T) {
	for _, nested := range []bool{false, true} {
		p := packetview.New(packetview.Limits{})
		ordinal := uint64(0)
		process := func(ip []byte, at int64) gopacket.Packet {
			ordinal++
			pkt := testutil.Packet(testutil.Ethernet(ip), 0, ordinal)
			pkt.Metadata().Timestamp = time.Unix(0, at)
			return p.Process(pkt, ordinal).Packet
		}
		ip := testutil.TCP(false, false, 1, 0, "S", "")
		a := testutil.Fragment(ip, 1, 0, 16, true)
		b := testutil.Fragment(ip, 1, 16, len(ip)-20, false)
		if nested {
			a = testutil.Tunnel("gre", 3, a)
			b = testutil.Tunnel("gre", 3, b)
		}
		if process(a, 0) != nil {
			t.Fatal("incomplete transport admitted")
		}
		engine, err := New(DefaultConfig())
		if err != nil {
			t.Fatal(err)
		}
		scope := Scope{Sensor: "fixture", Interface: "pcap"}
		observe := func(pkt gopacket.Packet, at int64) {
			t.Helper()
			events := PacketEvents(pkt, scope)
			if len(events) != 1 || events[0].At != at {
				t.Fatalf("nested=%t: events=%+v, want time %d", nested, events, at)
			}
			if _, err := engine.Observe(events[0]); err != nil {
				t.Fatal(err)
			}
		}
		observe(process(ip, 1e9), 1e9)
		var completed gopacket.Packet
		if nested {
			if process(testutil.Fragment(b, 2, 0, 16, true), 2e9) != nil {
				t.Fatal("incomplete outer fragment admitted")
			}
			observe(process(ip, 3e9), 3e9)
			completed = process(testutil.Fragment(b, 2, 16, len(b)-20, false), 4e9)
		} else {
			completed = process(b, 4e9)
		}
		if completed == nil || completed.Metadata().Timestamp.UnixNano() != 0 {
			t.Fatal("missing reconstructed packet or earliest evidence time")
		}
		c := packetview.FromCapture(completed.Metadata().CaptureInfo)
		wantRefs := 2
		if nested {
			wantRefs = 3
		}
		if len(c.Packets) != wantRefs || c.Packets[0].Timestamp != 0 || c.Packets[len(c.Packets)-1].Timestamp != 4e9 {
			t.Fatalf("lost original capture refs: %+v", c.Packets)
		}
		observe(completed, 4e9)
		if engine.Stats().Late != 0 {
			t.Fatal("completed datagram dropped", engine.Stats())
		}
		// Ordinary epoch-zero packets retain capture time and the normal late policy.
		observe(process(ip, 0), 0)
		if engine.Stats().Late != 1 {
			t.Fatal("ordinary late packet was retimestamped", engine.Stats())
		}
	}
}

func TestFragmentCompletionAtEpoch(t *testing.T) {
	p := packetview.New(packetview.Limits{})
	ip := testutil.TCP(false, false, 1, 0, "S", "")
	parts := [][]byte{testutil.Fragment(ip, 1, 0, 16, true), testutil.Fragment(ip, 1, 16, len(ip)-20, false)}
	var completed gopacket.Packet
	for i, part := range parts {
		pkt := testutil.Packet(testutil.Ethernet(part), 0, uint64(i+1))
		pkt.Metadata().Timestamp = time.Unix(0, 0)
		completed = p.Process(pkt, uint64(i+1)).Packet
	}
	events := PacketEvents(completed, Scope{Sensor: "fixture", Interface: "pcap"})
	if len(events) != 1 || events[0].At != 0 {
		t.Fatalf("epoch-zero completion lost: %+v", events)
	}
	e, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Observe(events[0]); err != nil || e.Stats().Events != 1 || e.Stats().Late != 0 {
		t.Fatal("epoch-zero completion rejected", err, e.Stats())
	}
}
