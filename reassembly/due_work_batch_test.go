package reassembly

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// batchProbe inspects the assembler's retained scratch from inside a callback,
// which runs while a claimed batch is being processed.
type batchProbe struct {
	a        *Assembler
	flushing bool
	retained bool
}

func (f *batchProbe) flush(opt FlushOptions) (int, int) {
	f.flushing = true
	defer func() { f.flushing = false }()

	return f.a.FlushWithOptions(opt)
}

func (f *batchProbe) New(_, _ gopacket.Flow, _ AssemblerContext) Stream { return f }
func (f *batchProbe) Accept(*layers.TCP, TCPFlowDirection, Sequence) bool {
	return true
}

func (f *batchProbe) ReassembledSG(sg ScatterGather, _ AssemblerContext) {
	n, _ := sg.Lengths()
	sg.Fetch(n)
	f.retained = f.retained || (f.flushing && cap(f.a.dueBatch) != 0)
}

func (f *batchProbe) ReassemblyComplete(AssemblerContext, gopacket.Flow, string) bool { return true }

func dueGapPacket(seq uint32, syn bool, payload string) *layers.TCP {
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: seq, SYN: syn, ACK: true}
	if payload != "" {
		tcp.BaseLayer = layers.BaseLayer{Payload: []byte(payload)}
	}
	tcp.SetInternalPortsForTesting()

	return tcp
}

// A growing batch must not leave connection references behind in the array the
// assembler still retains, so the scratch is handed over for the whole flush.
func TestDueBatchHandoffDuringFlush(t *testing.T) {
	probe := &batchProbe{}
	p := NewStreamPool(probe)
	a := NewAssembler(p)
	probe.a = a
	base := time.Unix(1700000000, 0)
	ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: base})

	// Each round leaves a fresh sequence gap, so every connection queues a page.
	queue := func(round, count int) {
		for i := 0; i < count; i++ {
			k := snapshotKey(i)
			if _, ok := p.conns[k]; !ok {
				a.AssembleWithContext(k[0], dueGapPacket(1000, true, ""), &ctx)
			}
			a.AssembleWithContext(k[0], dueGapPacket(uint32(round)*100000+uint32(i)*100, false, "gap"), &ctx)
		}
	}

	opt := FlushOptions{T: base.Add(time.Second)}
	queue(1, 4)
	if flushed, _ := probe.flush(opt); flushed != 4 {
		t.Fatalf("warm flush = %d halves, want 4", flushed)
	}
	warm := cap(a.dueBatch)
	if warm == 0 {
		t.Fatal("warm flush retained no scratch")
	}

	// Force the batch to outgrow the retained array.
	queue(2, 64)
	if flushed, _ := probe.flush(opt); flushed != 64 {
		t.Fatalf("grown flush = %d halves, want 64", flushed)
	}
	if probe.retained {
		t.Fatal("assembler retained the scratch while a batch was claimed")
	}
	if cap(a.dueBatch) <= warm {
		t.Fatalf("retained capacity = %d, want more than %d", cap(a.dueBatch), warm)
	}
	for i, ref := range a.dueBatch[:cap(a.dueBatch)] {
		if ref != (connectionRef{}) {
			t.Fatalf("retained reference at index %d", i)
		}
	}
	if len(p.pendingDue) != 0 || len(p.closedDue) != 0 {
		t.Fatal("flushed connections remain indexed")
	}
}

// Sparse expiry removes individual entries instead of compacting the heap.
func TestDueBatchSparseRemoval(t *testing.T) {
	const size, due = 200, 3
	now := time.Unix(1700000000, 0)
	p := &StreamPool{conns: make(map[key]*connection), nextAlloc: 8, factory: &testFactoryBench{}}
	for i := 0; i < size; i++ {
		k := snapshotKey(i)
		ref, _ := p.getConnection(&k, false, now, nil)
		c := ref.conn
		c.mu.Lock()
		c.c2s.closed, c.s2c.closed = true, true
		c.c2s.lastSeen = now.Add(time.Duration(i) * time.Minute)
		c.s2c.lastSeen = c.c2s.lastSeen
		p.refreshDueLocked(c, false)
		c.mu.Unlock()
	}
	checkDueHeaps(t, p)

	a := &Assembler{connPool: p}
	refs := p.claimDue(nil, FlushOptions{TC: now.Add(due * time.Minute)})
	if len(refs) != due {
		t.Fatalf("claimed %d, want %d", len(refs), due)
	}
	if len(p.closedDue) != size-due {
		t.Fatalf("index size = %d, want %d", len(p.closedDue), size-due)
	}
	// Positions and ordering must stay valid after individual removals.
	checkDueHeaps(t, p)

	a.releaseDue(refs)
	if len(p.closedDue) != size {
		t.Fatalf("released index size = %d, want %d", len(p.closedDue), size)
	}
	checkDueHeaps(t, p)
}
