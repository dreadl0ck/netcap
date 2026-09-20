package reassembly

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type flushProgressStream struct {
	data        []byte
	completions int
}

func (s *flushProgressStream) Accept(*layers.TCP, TCPFlowDirection, Sequence) bool {
	return true
}

func (s *flushProgressStream) ReassembledSG(sg ScatterGather, _ AssemblerContext) {
	n, _ := sg.Lengths()
	s.data = append(s.data, sg.Fetch(n)...)
}

func (s *flushProgressStream) ReassemblyComplete(AssemblerContext, gopacket.Flow, string) bool {
	s.completions++
	return true
}

type flushProgressFactory struct {
	streams []*flushProgressStream
}

func (f *flushProgressFactory) New(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
	s := &flushProgressStream{}
	f.streams = append(f.streams, s)
	return s
}

func TestFlushAllProgressBufferedPages(t *testing.T) {
	const connections = 32
	factory := &flushProgressFactory{}
	pool := NewStreamPool(factory)
	a := NewAssembler(pool)
	want := make([][]byte, connections)
	for i := range connections {
		want[i] = bytes.Repeat([]byte{byte(i + 1)}, pageBytes+17)
		flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, byte(i + 1)}, []byte{10, 0, 1, 1})
		// Without a SYN, data stays buffered until the gap is flushed.
		a.assemble(flow, &layers.TCP{
			SrcPort:   layers.TCPPort(i + 1),
			DstPort:   80,
			Seq:       1000,
			BaseLayer: layers.BaseLayer{Payload: want[i]},
		})
	}
	if len(factory.streams) != connections {
		t.Fatalf("created %d streams, want %d", len(factory.streams), connections)
	}
	if a.pc.used != 2*connections || a.pc.used+len(a.pc.free) != a.pc.size {
		t.Fatalf("unexpected buffered page accounting: %s", a.Dump())
	}
	for i, s := range factory.streams {
		if len(s.data) != 0 || s.completions != 0 {
			t.Fatalf("stream %d delivered data or completed before flushing", i)
		}
	}

	for _, expectedClosed := range []int{connections, 0} {
		if closed := a.FlushAllProgress(); closed != expectedClosed {
			t.Errorf("closed %d connections, want %d", closed, expectedClosed)
		}
		for i, s := range factory.streams {
			if !bytes.Equal(s.data, want[i]) {
				t.Errorf("stream %d: flushed payload differs (got %d bytes, want %d)", i, len(s.data), len(want[i]))
			}
			if s.completions != 1 {
				t.Errorf("stream %d: completed %d times, want 1", i, s.completions)
			}
		}
		if remaining := len(pool.connections(nil)); remaining != 0 {
			t.Errorf("pool has %d connections after flush", remaining)
		}
		if a.pc.used != 0 || len(a.pc.free) != a.pc.size {
			t.Errorf("pages not returned after flush: %s", a.Dump())
		}
		seen := make(map[*page]bool, len(a.pc.free))
		for _, p := range a.pc.free {
			if p == nil || seen[p] {
				t.Fatal("page cache contains a nil or duplicate free page")
			}
			seen[p] = true
		}
	}
}
