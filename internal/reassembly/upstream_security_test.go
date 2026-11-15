package reassembly

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestSequenceWrapFullTurn(t *testing.T) {
	for _, pair := range [][2]Sequence{{uint32Max, 0}, {uint32Max - 2, 3}, {0, uint32Max}} {
		s, end := pair[0], pair[1]
		if got := s.add(s.difference(end)); got != end {
			t.Fatalf("%d + difference(%d) = %d", s, end, got)
		}
	}
}

func TestKeepFromAcrossContainers(t *testing.T) {
	a := NewAssembler(NewStreamPool(&testFactory{}))
	ac := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0)})
	live := &livePacket{bytes: []byte("abcd"), ac: &ac}
	queued := &livePacket{bytes: []byte("EFG"), seq: 4, ac: &ac}
	page, _, _ := queued.convertToPages(a.pc, 0, &ac)
	half := &halfconnection{pages: 1}
	a.cacheSG.all, a.cacheSG.toKeep = []byteContainer{live, page}, 2
	a.cleanSG(half, &ac)
	var got []byte
	for p := half.saved; p != nil; p = p.next {
		got = append(got, p.bytes...)
	}
	if !bytes.Equal(got, []byte("cdEFG")) || half.pages != 2 || a.pc.usedCount() != 2 {
		t.Fatalf("retained %q, half pages %d, allocated %d", got, half.pages, a.pc.usedCount())
	}
	a.addPending(half, 100) // Discontinuous saved data must release every page.
	if half.saved != nil || half.pages != 0 || a.pc.usedCount() != 0 {
		t.Fatal("discontinuous saved pages leaked")
	}
}

func TestPagesReturnToAllocatingCache(t *testing.T) {
	owner, borrower := newPageCache(), newPageCache()
	pages := make([]*page, 100)
	for i := range pages {
		pages[i] = owner.next(time.Time{})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for _, p := range pages {
			p.release(borrower)
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			p := owner.next(time.Time{})
			p.release(owner)
		}
	}()
	wg.Wait()
	if owner.usedCount() != 0 || borrower.usedCount() != 0 || borrower.size != 0 {
		t.Fatalf("owner=%d borrower=%d size=%d", owner.usedCount(), borrower.usedCount(), borrower.size)
	}
}

func TestUpstreamControlSegmentHandling(t *testing.T) {
	for _, flags := range []string{"S", "R", "F"} {
		t.Run(flags, func(t *testing.T) {
			p := newDuePair(false, false, 0)
			p.step(t, duePacket(0, false, 100, "S", "", 0))
			p.step(t, duePacket(0, false, 101, "", "abc", 1))
			p.step(t, duePacket(0, false, 102, flags, "", 2))
			p.step(t, duePacket(0, false, 104, "", "def", 3))
			for _, streams := range p.f[0].streams {
				if len(streams) != 1 {
					t.Fatal("stale control segment retired the connection")
				}
				s := streams[0]
				last := s.events[len(s.events)-1]
				if last.Kind != "data" || last.Bytes != "def" || last.End {
					t.Fatalf("continuation = %+v", last)
				}
			}
			p.step(t, dueOp{all: true})
		})
	}
}

func TestQueuedFINWithoutPayload(t *testing.T) {
	p := newDuePair(false, false, 0)
	p.step(t, duePacket(0, false, 100, "S", "", 0))
	p.step(t, duePacket(0, false, 104, "F", "", 1))
	p.step(t, duePacket(0, false, 101, "", "abc", 2))
	for _, streams := range p.f[0].streams {
		last := streams[0].events[len(streams[0].events)-1]
		if last.Kind != "data" || last.Bytes != "abc" || !last.End {
			t.Fatalf("FIN not delivered with preceding data: %+v", last)
		}
	}
	p.step(t, dueOp{all: true})
}

func TestTCPOptionStraddlingRetransmission(t *testing.T) {
	check := NewTCPOptionCheck()
	tcp := &layers.TCP{Seq: 99, BaseLayer: layers.BaseLayer{Payload: []byte("abc")}}
	if err := check.Accept(tcp, TCPDirClientToServer, 100); err != nil {
		t.Fatal(err)
	}
	tcp.Payload = []byte("a")
	if err := check.Accept(tcp, TCPDirClientToServer, 101); err == nil {
		t.Fatal("fully retransmitted payload accepted")
	}
}
