package reassembly

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func dueConcurrentPacket(t *testing.T, a *Assembler, flow int, seq uint32, flags, data string, seen int) {
	t.Helper()
	k := snapshotKey(flow)
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: seq, ACK: true}
	for _, flag := range flags {
		switch flag {
		case 'S':
			tcp.SYN = true
		case 'F':
			tcp.FIN = true
		}
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, tcp, gopacket.Payload(data)); err != nil {
		t.Fatal(err)
	}
	if err := tcp.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: dueTime(seen)})
	a.AssembleWithContext(k[0], tcp, &ctx)
}

func TestDueConcurrencyStaleClaimReuse(t *testing.T) {
	p := NewStreamPool(&dueFactory{streams: make(map[key][]*dueRecorder)})
	a := NewAssembler(p)
	opt := FlushOptions{T: dueTime(10), TC: dueTime(-10)}
	dueConcurrentPacket(t, a, 1, 100, "", "old", 1)
	refs := p.claimDue(nil, opt)
	if len(refs) != 1 || !refs[0].lock() {
		t.Fatal("missing old claim")
	}
	old := refs[0]
	p.remove(old.conn) // Removal, including ownership retirement, requires conn.mu.
	old.conn.mu.Unlock()
	dueConcurrentPacket(t, a, 2, 100, "", "new", 2)
	current := p.connections(nil)[0]
	if current.conn != old.conn || current.generation == old.generation {
		t.Fatal("fixture did not reuse the slot with a new generation")
	}
	for _, claimed := range []bool{false, true} {
		var owned []connectionRef
		if claimed {
			owned = p.claimDue(nil, opt)
			if len(owned) != 1 || owned[0] != current {
				t.Fatal("missing new-generation claim")
			}
		}
		if f, c := a.flushDue(old, opt); f != 0 || c != 0 {
			t.Fatalf("stale flush = %d, %d", f, c)
		}
		a.releaseDue([]connectionRef{old})
		if current.conn.dueClaimed != claimed {
			t.Fatal("stale release changed new-generation ownership")
		}
		checkDueHeaps(t, p)
		if claimed {
			a.releaseDue(owned)
		}
	}
	if f, c := a.FlushWithOptions(opt); f != 1 || c != 0 {
		t.Fatalf("new generation flush = %d, %d", f, c)
	}
	checkDueHeaps(t, p)
}

func TestDueConcurrencyClaimedHeadMutation(t *testing.T) {
	p := NewStreamPool(&dueFactory{streams: make(map[key][]*dueRecorder)})
	owner, packets := NewAssembler(p), NewAssembler(p)
	dueConcurrentPacket(t, packets, 1, 100, "S", "", 0)
	dueConcurrentPacket(t, packets, 1, 110, "", "old", 2)
	for _, seen := range []int{8, -2} {
		refs := p.claimDue(nil, FlushOptions{T: dueTime(20)})
		if len(refs) != 1 {
			t.Fatal("missing claim")
		}
		dueConcurrentPacket(t, packets, 1, 110, "", "new", seen)
		checkDueHeaps(t, p)
		if !refs[0].conn.due.pending.Equal(dueTime(seen)) {
			t.Fatal("claimed head deadline was not refreshed")
		}
		if again := p.claimDue(nil, FlushOptions{T: dueTime(20)}); len(again) != 0 {
			t.Fatal("second caller borrowed an owned generation")
		}
		owner.releaseDue(refs)
		checkDueHeaps(t, p)
		if len(p.pendingDue) != 1 || !p.pendingDue[0].deadline.Equal(dueTime(seen)) {
			t.Fatal("release did not publish the actual head")
		}
	}
	if f, c := owner.FlushWithOptions(FlushOptions{T: dueTime(0)}); f != 1 || c != 0 {
		t.Fatalf("earlier head flush = %d, %d", f, c)
	}
}

func TestDueConcurrencyClaimedCompletion(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(fmt.Sprint(retain), func(t *testing.T) {
			factory := &dueFactory{streams: make(map[key][]*dueRecorder), retain: retain}
			p := NewStreamPool(factory)
			a := NewAssembler(p)
			dueConcurrentPacket(t, a, 1, 100, "F", "fin", 1)
			ref := p.connections(nil)[0]
			if !ref.lock() {
				t.Fatal("missing connection")
			}
			a.closeHalfConnection(ref.conn, &ref.conn.s2c, "fixture")
			p.refreshDueLocked(ref.conn, false)
			ref.conn.mu.Unlock()
			refs := p.claimDue(nil, FlushOptions{T: dueTime(2)})
			if len(refs) != 1 {
				t.Fatal("missing FIN claim")
			}
			if f, c := a.flushDue(refs[0], FlushOptions{T: dueTime(2), TC: dueTime(-1)}); f != 1 || c != 1 {
				t.Fatalf("FIN flush = %d, %d", f, c)
			}
			a.releaseDue(refs)
			checkDueHeaps(t, p)
			if ref.conn.live != retain || ref.conn.dueClaimed || (len(p.closedDue) == 1) != retain {
				t.Fatal("completion return value did not control retirement/indexing")
			}
			n := 0
			for _, e := range factory.streams[snapshotKey(1)][0].events {
				if e.Kind == "complete" {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("completion callbacks = %d", n)
			}
			a.FlushWithOptions(FlushOptions{TC: dueTime(2)})
			if len(p.connections(nil)) != 0 {
				t.Fatal("retained closed generation did not expire")
			}
		})
	}
}

type duePanicRecorder struct {
	dueRecorder
	hook func()
}

func (s *duePanicRecorder) ReassembledSG(sg ScatterGather, ac AssemblerContext) {
	s.dueRecorder.ReassembledSG(sg, ac)
	if s.hook != nil {
		s.hook()
	}
}

func TestDueConcurrencyFiniteBatch(t *testing.T) {
	p := NewStreamPool(&dueFactory{streams: make(map[key][]*dueRecorder)})
	a, packets := NewAssembler(p), NewAssembler(p)
	dueConcurrentPacket(t, packets, 1, 100, "", "first", 1)
	ref := p.connections(nil)[0]
	if !ref.lock() {
		t.Fatal("missing connection")
	}
	opt := FlushOptions{T: dueTime(10)}
	claimed := make(chan []connectionRef, 1)
	go func() { claimed <- p.claimDue(nil, opt) }()
	var refs []connectionRef
	select {
	case refs = <-claimed:
	case <-time.After(5 * time.Second):
		ref.conn.mu.Unlock()
		t.Fatal("claim waited for a connection lock")
	}
	ref.conn.mu.Unlock()
	if len(refs) != 1 || refs[0] != ref {
		t.Fatal("claim did not select the indexed generation")
	}
	a.releaseDue(refs)
	s := &duePanicRecorder{hook: func() {
		dueConcurrentPacket(t, packets, 2, 100, "", "published during callback", 2)
	}}
	if !ref.lock() {
		t.Fatal("connection retired before callback installation")
	}
	ref.conn.c2s.stream, ref.conn.s2c.stream = s, s
	ref.conn.mu.Unlock()
	for call := 0; call < 2; call++ {
		if f, c := a.FlushWithOptions(opt); f != 1 || c != 0 {
			t.Fatalf("finite batch call %d = %d, %d", call, f, c)
		}
		checkDueHeaps(t, p)
		if len(p.pendingDue) != 1-call {
			t.Fatal("newly published work was lost or consumed in the original batch")
		}
	}
}

func TestDueConcurrencyPublicFlushPanic(t *testing.T) {
	p := NewStreamPool(&dueFactory{streams: make(map[key][]*dueRecorder)})
	a := NewAssembler(p)
	for i := 1; i <= 3; i++ {
		dueConcurrentPacket(t, a, i, 100, "", "first", i)
		dueConcurrentPacket(t, a, i, 120, "", "second", 5)
	}
	c := p.conns[snapshotKey(1)]
	a.dueBatch = make([]connectionRef, 0, 3)
	scratch := a.dueBatch[:cap(a.dueBatch)]
	s := &duePanicRecorder{hook: func() {
		if scratch[0] != (connectionRef{}) || scratch[1].conn == nil || scratch[2].conn == nil || !c.dueClaimed {
			t.Error("public flush did not transfer only the current claim")
		}
		panic("user callback")
	}}
	c.mu.Lock()
	c.c2s.stream, c.s2c.stream = s, s
	c.mu.Unlock()
	finished := make(chan any, 1)
	go func() {
		defer func() { finished <- recover() }()
		a.FlushWithOptions(FlushOptions{T: dueTime(10)})
	}()
	select {
	case got := <-finished:
		if got != "user callback" {
			t.Fatalf("recovered %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("panic cleanup deadlocked")
	}
	for _, ref := range p.connections(nil) {
		if !ref.conn.mu.TryLock() {
			t.Fatal("panic left a connection locked")
		}
		ref.conn.mu.Unlock()
		if ref.conn.dueClaimed {
			t.Fatal("panic lost a claim")
		}
	}
	checkDueHeaps(t, p)
	checkDueBatchCleared(t, a)
	s.hook = nil
	if f, c := a.FlushWithOptions(FlushOptions{T: dueTime(10)}); f != 3 || c != 0 {
		t.Fatalf("continued flush = %d, %d; want all three remaining heads", f, c)
	}
	if f, c := a.FlushWithOptions(FlushOptions{T: dueTime(10)}); f != 0 || c != 0 {
		t.Fatalf("repeat flush = %d, %d", f, c)
	}
	checkDueHeaps(t, p)
}

func TestDueConcurrencyParallelMatchesSerial(t *testing.T) {
	run := func(parallel bool) map[key][][]dueEvent {
		factory := &dueFactory{streams: make(map[key][]*dueRecorder)}
		p := NewStreamPool(factory)
		workers := [4]*Assembler{NewAssembler(p), NewAssembler(p), NewAssembler(p), NewAssembler(p)}
		phase := func(fn func(int, *Assembler)) {
			start, done := make(chan struct{}), make(chan struct{}, len(workers))
			for i, a := range workers {
				if parallel {
					go func() { <-start; defer func() { done <- struct{}{} }(); fn(i, a) }()
				} else {
					fn(i, a)
				}
			}
			close(start)
			if parallel {
				for range workers {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("parallel phase deadlocked")
					}
				}
			}
		}
		for epoch := 0; epoch < 2; epoch++ {
			for round := 1; round <= 8; round++ {
				phase(func(i int, a *Assembler) {
					dueConcurrentPacket(t, a, i, uint32(round*100), "", fmt.Sprintf("%d/%d/%d", epoch, i, round), round)
					a.FlushWithOptions(FlushOptions{T: dueTime(round)})
				}) // All delayed packets are queued before any eligible flush.
				counts := [4]int{}
				phase(func(i int, a *Assembler) { counts[i], _ = a.FlushWithOptions(FlushOptions{T: dueTime(round + 1)}) })
				if counts[0]+counts[1]+counts[2]+counts[3] != 4 {
					t.Fatalf("epoch %d round %d lost/duplicated claims: %v", epoch, round, counts)
				}
				checkDueHeaps(t, p)
			}
			workers[0].FlushAll()
			p.Reset() // Every worker has crossed the final barrier.
		}
		return factory.records()
	}
	if got, want := run(true), run(false); !reflect.DeepEqual(got, want) {
		t.Fatalf("parallel per-flow callbacks differ from serial:\ngot %#v\nwant %#v", got, want)
	}
}

func TestDueConcurrencyResetRoots(t *testing.T) {
	p := retainedDuePool(1, dueTime(1))
	a := NewAssembler(p)
	dueConcurrentPacket(t, a, 1, 100, "", "before", 1)
	old := p.connections(nil)
	if len(p.pendingDue) != 1 || len(p.closedDue) != 1 {
		t.Fatal("fixture needs both roots")
	}
	p.Reset()
	if p.pendingDue != nil || p.closedDue != nil || p.all != nil || len(p.connections(nil)) != 0 {
		t.Fatal("reset retained roots or connection storage")
	}
	dueConcurrentPacket(t, a, 1, 100, "", "after", 2)
	for _, ref := range old {
		if ref.lock() {
			ref.conn.mu.Unlock()
			t.Fatal("pre-reset reference is still live")
		}
		a.flushDue(ref, FlushOptions{T: dueTime(10), TC: dueTime(10)})
	}
	a.releaseDue(old)
	checkDueHeaps(t, p)
	if f, c := a.FlushWithOptions(FlushOptions{T: dueTime(10)}); f != 1 || c != 0 {
		t.Fatalf("post-reset flush = %d, %d", f, c)
	}
	checkDueHeaps(t, p)
}
