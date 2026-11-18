package reassembly

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestPartialQueuedOverlapPreservesPrefix(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(fmt.Sprint(bounded), func(t *testing.T) {
			factory := new(flushProgressFactory)
			a := NewAssembler(NewStreamPool(factory))
			if bounded {
				budget, err := NewPageBudget(16*PageAllocationBytes, nil)
				if err != nil {
					t.Fatal(err)
				}
				a.SetPageBudget(budget)
			}
			flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
			for _, part := range []struct {
				seq  uint32
				data string
			}{{100, "aaaa"}, {104, "bbbb"}, {108, "cc"}, {105, "BBBBB"}} {
				a.assemble(flow, &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: part.seq, BaseLayer: layers.BaseLayer{Payload: []byte(part.data)}})
			}
			a.FlushAll()
			if !bytes.Equal(factory.streams[0].data, []byte("aaaabBBBBB")) {
				t.Fatalf("overlap lost queued prefix: %q", factory.streams[0].data)
			}
			if a.pc.used != 0 {
				t.Fatalf("orphaned pages: %d", a.pc.used)
			}
			a.Release()
		})
	}
}

func TestDisjointGapFillDeliversAcrossRollover(t *testing.T) {
	for _, tc := range []struct {
		name string
		isn  uint32
		fast bool
	}{
		{"ordinary", 100, true},
		{"input crosses rollover", ^uint32(0) - 5, true},
		{"queue across rollover", ^uint32(0) - 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			factory := new(flushProgressFactory)
			pool := NewStreamPool(factory)
			a := NewAssembler(pool)
			defer a.Release()
			budget, err := NewPageBudget(64*PageAllocationBytes, nil)
			if err != nil {
				t.Fatal(err)
			}
			a.SetPageBudget(budget)
			flow := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{192, 0, 2, 2})
			send := func(offset uint32, syn bool, data []byte) {
				a.assemble(flow, &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: tc.isn + offset, SYN: syn, BaseLayer: layers.BaseLayer{Payload: data}})
			}
			send(0, true, nil)
			send(1, false, []byte("head"))
			tail := make([]byte, 64)
			for i := range tail {
				tail[i] = byte(i)
				send(9+uint32(i), false, tail[i:i+1])
			}
			conns := pool.connections(nil)
			if len(conns) != 1 {
				t.Fatalf("connections = %d", len(conns))
			}
			half := &conns[0].conn.c2s
			if half.pages != len(tail) || half.endsBeforeQueue(Sequence(tc.isn+7)) != tc.fast {
				t.Fatalf("unexpected queued state: pages=%d, fast path=%t", half.pages, half.endsBeforeQueue(Sequence(tc.isn+7)))
			}
			send(5, false, []byte("ab"))
			if got := factory.streams[0].data; string(got) != "headab" || half.pages != len(tail) {
				t.Fatalf("disjoint input disturbed queue: delivered=%q pages=%d", got, half.pages)
			}
			send(7, false, []byte("cd"))
			if got, want := factory.streams[0].data, append([]byte("headabcd"), tail...); !bytes.Equal(got, want) {
				t.Fatalf("assembled payload = %q, want %q", got, want)
			}
			a.FlushAll()
			if health := budget.Health(); a.pc.used != 0 || health.RetainedBytes != 0 || health.Exceeded || factory.streams[0].completions != 1 {
				t.Fatalf("retained pages=%d, completions=%d, budget=%+v", a.pc.used, factory.streams[0].completions, health)
			}
		})
	}
}

func TestCapturePageOwnership(t *testing.T) {
	path := os.Getenv("NETCAP_REASSEMBLY_PCAP")
	if path == "" {
		t.Skip("set NETCAP_REASSEMBLY_PCAP")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAssembler(NewStreamPool(new(flushProgressFactory)))
	for i := 0; ; i++ {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		if tcp, ok := p.TransportLayer().(*layers.TCP); ok && p.NetworkLayer() != nil {
			ac := assemblerSimpleContext(ci)
			a.AssembleWithContext(p.NetworkLayer().NetworkFlow(), tcp, &ac)
			pages := 0
			for _, ref := range a.connPool.connections(nil) {
				for _, half := range []*halfconnection{&ref.conn.c2s, &ref.conn.s2c} {
					for _, head := range []*page{half.first, half.saved} {
						for p := head; p != nil; p = p.next {
							pages++
						}
					}
				}
			}
			if pages != a.pc.used {
				t.Fatalf("packet %d: reachable=%d allocated=%d", i+1, pages, a.pc.used)
			}
		}
	}
	a.FlushAll()
	a.Release()
}
