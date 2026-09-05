package reassembly

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func snapshotKey(i int) key {
	return key{gopacket.NewFlow(layers.EndpointIPv4,
		[]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}, []byte{192, 0, 2, 1}),
		gopacket.NewFlow(layers.EndpointTCPPort, []byte{0x30, 0x39}, []byte{0, 80})}
}

func checkDueBatchCleared(t *testing.T, a *Assembler) {
	t.Helper()
	if len(a.dueBatch) != 0 {
		t.Fatalf("retained length = %d, want 0", len(a.dueBatch))
	}
	for i, c := range a.dueBatch[:cap(a.dueBatch)] {
		if c != (connectionRef{}) {
			t.Fatalf("retained reference at index %d", i)
		}
	}
}

func TestPoolSnapshotMembership(t *testing.T) {
	p := &StreamPool{conns: make(map[key]*connection), nextAlloc: 2, factory: &testFactoryBench{}}
	now := time.Unix(1700000000, 0)
	add := func(i int) *connection {
		k := snapshotKey(i)
		ref, _ := p.getConnection(&k, false, now, nil)
		return ref.conn
	}
	var dst []connectionRef
	check := func(want ...*connection) {
		t.Helper()
		dst = p.connections(dst)
		if len(dst) != len(want) {
			t.Fatalf("snapshot length = %d, want %d", len(dst), len(want))
		}
		seen := make(map[*connection]bool)
		for _, ref := range dst {
			c := ref.conn
			if seen[c] {
				t.Fatal("duplicate connection in snapshot")
			}
			seen[c] = true
		}
		for _, c := range want {
			if !seen[c] {
				t.Fatal("snapshot missing current connection")
			}
		}
	}
	check()
	c1 := add(1)
	check(c1)
	old := &dst[0]
	c2, c3 := add(2), add(3)
	check(c1, c2, c3)
	if cap(dst) != 3 || &dst[0] == old {
		t.Fatal("growth must allocate exactly the pool size")
	}
	old = &dst[0]
	c2.mu.Lock()
	p.remove(c2)
	c2.mu.Unlock()
	check(c1, c3)
	if &dst[0] != old {
		t.Fatal("shrink did not reuse storage")
	}
	c4 := add(4)
	if c4 != c2 || *c4.key != snapshotKey(4) {
		t.Fatal("fixture did not recycle removed connection")
	}
	check(c1, c3, c4)
	p.Reset()
	check()
	c5 := add(5)
	check(c5)
	if &dst[0] != old {
		t.Fatal("reset should refresh membership, not discard caller storage")
	}
	if allocs := testing.AllocsPerRun(100, func() { dst = p.connections(dst) }); allocs != 0 {
		t.Fatalf("warmed snapshot allocations = %g, want 0", allocs)
	}
}

func retainedDuePool(size int, deadline time.Time) *StreamPool {
	p := &StreamPool{conns: make(map[key]*connection), nextAlloc: 8, factory: &testFactoryBench{}}
	for i := 0; i < size; i++ {
		k := snapshotKey(i)
		ref, _ := p.getConnection(&k, false, deadline, nil)
		c := ref.conn
		c.mu.Lock()
		c.c2s.closed, c.s2c.closed = true, true
		p.refreshDueLocked(c, false)
		c.mu.Unlock()
	}
	return p
}

func TestDueBatchReuseAndClear(t *testing.T) {
	now := time.Unix(1700000000, 0)
	p := retainedDuePool(8, now.Add(time.Hour))
	a := &Assembler{connPool: p}
	if f, c := a.FlushWithOptions(FlushOptions{T: now, TC: now}); f != 0 || c != 0 || cap(a.dueBatch) != 0 {
		t.Fatal("future deadlines allocated a batch or performed work")
	}
	if len(p.closedDue) != 8 || len(p.pendingDue) != 0 {
		t.Fatal("retained connections are not indexed")
	}
	opt := FlushOptions{TC: now.Add(2 * time.Hour)}
	claimRelease := func(want int) {
		t.Helper()
		refs := p.claimDue(a.dueBatch, opt)
		if len(refs) != want || len(p.closedDue) != 0 {
			t.Fatalf("claimed %d, want %d; remaining index = %d", len(refs), want, len(p.closedDue))
		}
		a.releaseDue(refs)
		checkDueBatchCleared(t, a)
		if len(p.closedDue) != want {
			t.Fatalf("released index size = %d, want %d", len(p.closedDue), want)
		}
	}
	claimRelease(8)
	storage := &a.dueBatch[:cap(a.dueBatch)][0]
	for i := 1; i < 8; i++ {
		c := p.conns[snapshotKey(i)]
		c.mu.Lock()
		p.remove(c)
		c.mu.Unlock()
	}
	claimRelease(1)
	if allocs := testing.AllocsPerRun(100, func() {
		a.releaseDue(p.claimDue(a.dueBatch, opt))
	}); allocs != 0 {
		t.Fatalf("warmed claim/release allocations = %g, want 0", allocs)
	}
	p.Reset()
	claimRelease(0)
	if &a.dueBatch[:cap(a.dueBatch)][0] != storage {
		t.Fatal("shrinking/empty pool discarded reusable storage")
	}
}

func TestDueBatchRetentionLimit(t *testing.T) {
	if maxDueBatchConnections != 64*1024 {
		t.Fatalf("due batch limit = %d, want 64k references", maxDueBatchConnections)
	}
	for _, capacity := range []int{maxDueBatchConnections, maxDueBatchConnections + 1} {
		for _, warm := range []bool{false, true} {
			t.Run(strconv.Itoa(capacity)+"/warm="+strconv.FormatBool(warm), func(t *testing.T) {
				now := time.Unix(1700000000, 0)
				p := retainedDuePool(8, now.Add(time.Hour))
				a := &Assembler{connPool: p}
				opt := FlushOptions{TC: now.Add(2 * time.Hour)}
				if warm {
					a.releaseDue(p.claimDue(nil, opt))
				}
				old := a.dueBatch
				// Supply oversized scratch directly; every claimed reference still
				// comes from a distinct, genuinely indexed connection.
				scratch := make([]connectionRef, 0, capacity)
				refs := p.claimDue(scratch, opt)
				if len(refs) != 8 || len(p.closedDue) != 0 {
					t.Fatalf("claim size = %d, remaining index = %d", len(refs), len(p.closedDue))
				}
				a.releaseDue(refs)
				checkDueBatchCleared(t, a)
				for i, ref := range scratch[:cap(scratch)] {
					if ref != (connectionRef{}) {
						t.Fatalf("scratch retains reference at %d", i)
					}
				}
				if len(p.closedDue) != 8 || len(p.conns) != 8 {
					t.Fatal("release did not restore indexed membership")
				}
				if capacity == maxDueBatchConnections {
					if cap(a.dueBatch) != capacity || &a.dueBatch[:capacity][0] != &scratch[:capacity][0] {
						t.Fatal("boundary-sized scratch was not retained")
					}
				} else if cap(a.dueBatch) != cap(old) {
					t.Fatal("oversized scratch replaced retained storage")
				} else if warm && &a.dueBatch[:1][0] != &old[:1][0] {
					t.Fatal("oversized scratch replaced warmed storage")
				}
			})
		}
	}
}

func TestDueBatchFlushClearsRemovedReferences(t *testing.T) {
	now := time.Unix(1700000000, 0)
	p := retainedDuePool(8, now)
	a := &Assembler{connPool: p}
	if f, c := a.FlushWithOptions(FlushOptions{TC: now.Add(time.Second)}); f != 0 || c != 0 {
		t.Fatalf("already-closed flush = (%d, %d)", f, c)
	}
	if len(p.conns) != 0 || len(p.closedDue) != 0 || cap(a.dueBatch) < 8 {
		t.Fatal("due flush did not remove indexed connections and retain scratch")
	}
	checkDueBatchCleared(t, a)
}

func TestDueBatchTimestampBoundary(t *testing.T) {
	tc := time.Unix(1700000000, 0)
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		for _, reverse := range []bool{false, true} {
			t.Run(delta.String()+"/reverse="+strconv.FormatBool(reverse), func(t *testing.T) {
				k := snapshotKey(1)
				c := &connection{}
				c.reset(&k, nil, tc.Add(-time.Second))
				c.c2s.closed, c.s2c.closed = true, true
				if reverse {
					c.s2c.lastSeen = tc.Add(delta)
				} else {
					c.c2s.lastSeen = tc.Add(delta)
				}
				p := &StreamPool{conns: map[key]*connection{k: c}}
				c.mu.Lock()
				p.refreshDueLocked(c, false)
				c.mu.Unlock()
				if len(p.closedDue) != 1 {
					t.Fatal("closed connection not indexed")
				}
				a := &Assembler{connPool: p}
				if f, n := a.FlushWithOptions(FlushOptions{T: tc, TC: tc}); f != 0 || n != 0 {
					t.Fatalf("already-closed flush = (%d, %d)", f, n)
				}
				if removed := p.conns[k] == nil; removed != (delta < 0) {
					t.Fatalf("removed = %v, want %v", removed, delta < 0)
				}
				checkDueBatchCleared(t, a)
			})
		}
	}
	k := snapshotKey(2)
	c := &connection{}
	c.reset(&k, nil, tc.Add(-time.Hour))
	p := &StreamPool{conns: map[key]*connection{k: c}}
	c.mu.Lock()
	p.refreshDueLocked(c, false)
	c.mu.Unlock()
	a := &Assembler{connPool: p}
	if f, n := a.FlushWithOptions(FlushOptions{T: tc}); f != 0 || n != 0 {
		t.Fatalf("zero-TC flush = (%d, %d)", f, n)
	}
	if p.conns[k] != c || c.c2s.closed || c.s2c.closed || !c.c2s.lastSeen.Equal(tc.Add(-time.Hour)) || !c.s2c.lastSeen.Equal(tc.Add(-time.Hour)) {
		t.Fatal("zero TC changed idle open connection")
	}
	checkDueBatchCleared(t, a)
}

func TestDueBatchSeparateAssemblers(t *testing.T) {
	p := &StreamPool{conns: make(map[key]*connection), nextAlloc: 16, factory: &testFactoryBench{}}
	for i := 0; i < 16; i++ {
		k := snapshotKey(i)
		p.getConnection(&k, false, time.Unix(1700000000, 0), nil)
	}
	assemblers := []*Assembler{{connPool: p}, {connPool: p}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, a := range assemblers {
		wg.Add(1)
		go func(a *Assembler) {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				if f, c := a.FlushWithOptions(FlushOptions{}); f != 0 || c != 0 {
					t.Errorf("no-op flush = (%d, %d)", f, c)
				}
			}
		}(a)
	}
	close(start)
	wg.Wait()
	for _, a := range assemblers {
		checkDueBatchCleared(t, a)
		if cap(a.dueBatch) != 0 {
			t.Fatalf("retained capacity = %d, want 0", cap(a.dueBatch))
		}
	}
	if len(p.pendingDue) != 0 || len(p.closedDue) != 0 {
		t.Fatal("idle open connections entered due indexes")
	}
	if len(p.conns) != 16 {
		t.Fatal("simultaneous no-op flush changed membership")
	}
}
