package reassembly

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestPageBudgetReservationIsAtomicAndReleasesCache(t *testing.T) {
	var cancels atomic.Int64
	b, err := NewPageBudget(2*PageAllocationBytes, func() { cancels.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	pc := newPageCache()
	pc.budget = b
	lp := livePacket{bytes: make([]byte, pageBytes+1), ac: &assemblerSimpleContext{Timestamp: time.Unix(1, 0)}}
	first, last, count := lp.convertToPages(pc, 0, lp.ac)
	if first == nil || last == first || count != 2 || b.Health().RetainedBytes != 2*PageAllocationBytes {
		t.Fatal("multi-page reservation was not exact", b.Health())
	}
	if p, _, _ := lp.convertToPages(pc, 0, lp.ac); p != nil || pc.used != 2 || cancels.Load() != 1 || !errors.Is(b.Error(), ErrPageBudget) {
		t.Fatal("over-budget packet partially allocated", b.Health())
	}
	pc.replace(first)
	pc.replace(last)
	if pc.used != 0 || pc.size != 0 || len(pc.free) != 0 || b.Health().RetainedBytes != 0 || first.ac != nil || last.ac != nil {
		t.Fatal("released pages retained cache or context references", b.Health())
	}
}

func TestPageBudgetSharedAcrossConcurrentAssemblers(t *testing.T) {
	for _, workers := range []int{1, 2, 4, 8} {
		var cancels atomic.Int64
		b, _ := NewPageBudget(PageAllocationBytes, func() { cancels.Add(1) })
		var wg sync.WaitGroup
		start := make(chan struct{})
		var successes atomic.Int64
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				pc := newPageCache()
				pc.budget = b
				lp := livePacket{bytes: []byte("x"), ac: &assemblerSimpleContext{}}
				p, _, _ := lp.convertToPages(pc, 0, lp.ac)
				if p != nil {
					successes.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if successes.Load() != 1 || b.Health().PeakBytes != PageAllocationBytes || (workers > 1 && cancels.Load() != 1) {
			t.Fatal(workers, successes.Load(), b.Health())
		}
	}
}

func TestPageBudgetCanReuseConsumedPages(t *testing.T) {
	b, _ := NewPageBudget(PageAllocationBytes, nil)
	pc := newPageCache()
	pc.budget = b
	for range 100 {
		lp := livePacket{bytes: []byte("x"), ac: &assemblerSimpleContext{}}
		p, _, _ := lp.convertToPages(pc, 0, lp.ac)
		if p == nil {
			t.Fatal("consumed reservation was not reusable")
		}
		pc.replace(p)
	}
	if b.Error() != nil || b.Health().RetainedBytes != 0 {
		t.Fatal(b.Health())
	}
}

type retainingPageStream struct{ discarded int }

func (s *retainingPageStream) New(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream { return s }
func (*retainingPageStream) Accept(*layers.TCP, TCPFlowDirection, Sequence) bool         { return true }
func (*retainingPageStream) ReassemblyComplete(AssemblerContext, gopacket.Flow, string) bool {
	return true
}
func (*retainingPageStream) ReassembledSG(sg ScatterGather, _ AssemblerContext) {
	if n, _ := sg.Lengths(); n > 0 {
		sg.KeepFrom(0)
	}
}
func (s *retainingPageStream) ReassemblyDiscarded(_ TCPFlowDirection, n int, _ AssemblerContext) {
	s.discarded += n
}

func TestPageBudgetAlsoBoundsKeepFromAndClearsScratch(t *testing.T) {
	s := new(retainingPageStream)
	b, _ := NewPageBudget(PageAllocationBytes, nil)
	a := NewAssembler(NewStreamPool(s))
	a.SetPageBudget(b)
	network := gopacket.NewFlow(layers.EndpointIPv4, []byte{192, 0, 2, 1}, []byte{198, 51, 100, 1})
	ctx := &assemblerSimpleContext{Timestamp: time.Unix(1, 0)}
	a.AssembleWithContext(network, &layers.TCP{SrcPort: 12345, DstPort: 80, SYN: true, Seq: 100}, ctx)
	for _, seq := range []uint32{101, 102} {
		packet := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: seq, ACK: true, Window: 4096}
		packet.Payload = []byte("x")
		a.AssembleWithContext(network, packet, ctx)
		if len(a.ret) != 0 || len(a.cacheSG.all) != 0 || a.cacheLP.bytes != nil {
			t.Fatal("scratch retained a delivered page or packet")
		}
	}
	if !errors.Is(b.Error(), ErrPageBudget) || s.discarded != 1 || b.Health().PeakBytes != PageAllocationBytes {
		t.Fatal("KeepFrom bypassed shared allocation budget", b.Health(), s.discarded)
	}
	a.FlushAll()
	if b.Health().RetainedBytes != 0 {
		t.Fatal("saved pages did not release at completion", b.Health())
	}
}

func TestClosedHalfReleasesEveryQueuedAndSavedPage(t *testing.T) {
	for _, limit := range []int64{0, 10 * PageAllocationBytes} {
		b, _ := NewPageBudget(limit, nil)
		a := NewAssembler(NewStreamPool(new(retainingPageStream)))
		a.SetPageBudget(b)
		conn := new(connection)
		lp := livePacket{bytes: make([]byte, 3*pageBytes), ac: &assemblerSimpleContext{}}
		conn.c2s.first, conn.c2s.last, _ = lp.convertToPages(a.pc, 0, lp.ac)
		conn.c2s.saved, _, _ = lp.convertToPages(a.pc, 0, lp.ac)
		conn.c2s.pages = 6
		a.closeHalfConnection(conn, &conn.c2s, "test")
		if a.pc.used != 0 || conn.c2s.first != nil || conn.c2s.last != nil || conn.c2s.saved != nil || conn.c2s.pages != 0 {
			t.Fatal("closed half retained page chains", limit, a.pc.used)
		}
		if b != nil && b.Health().RetainedBytes != 0 {
			t.Fatal(b.Health())
		}
	}
}
