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

func checkSnapshotCleared(t *testing.T, a *Assembler) {
	t.Helper()
	if len(a.flushSnapshot) != 0 {
		t.Fatalf("retained length = %d, want 0", len(a.flushSnapshot))
	}
	for i, c := range a.flushSnapshot[:cap(a.flushSnapshot)] {
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

func TestFlushSnapshotReuseAndClear(t *testing.T) {
	p := &StreamPool{conns: make(map[key]*connection)}
	for i := 0; i < 8; i++ {
		p.conns[snapshotKey(i)] = &connection{live: true}
	}
	a := &Assembler{connPool: p}
	flush := func() {
		t.Helper()
		if f, c := a.FlushWithOptions(FlushOptions{}); f != 0 || c != 0 {
			t.Fatalf("no-op flush = (%d, %d)", f, c)
		}
		checkSnapshotCleared(t, a)
	}
	flush()
	if cap(a.flushSnapshot) != 8 {
		t.Fatalf("retained capacity = %d, want 8", cap(a.flushSnapshot))
	}
	storage := &a.flushSnapshot[:cap(a.flushSnapshot)][0]
	for i := 1; i < 8; i++ {
		delete(p.conns, snapshotKey(i))
	}
	flush()
	if allocs := testing.AllocsPerRun(100, func() { a.FlushWithOptions(FlushOptions{}) }); allocs != 0 {
		t.Fatalf("warmed flush allocations = %g, want 0", allocs)
	}
	p.Reset()
	flush()
	if cap(a.flushSnapshot) != 8 || &a.flushSnapshot[:8][0] != storage {
		t.Fatal("shrinking/empty pool discarded reusable storage")
	}
}

func TestFlushSnapshotRetentionLimit(t *testing.T) {
	if maxFlushSnapshotConnections != 64*1024 {
		t.Fatalf("snapshot limit = %d, want 64k 16-byte references (1 MiB)", maxFlushSnapshotConnections)
	}
	for _, size := range []int{maxFlushSnapshotConnections, maxFlushSnapshotConnections + 1} {
		for _, warm := range []bool{false, true} {
			t.Run(strconv.Itoa(size)+"/warm="+strconv.FormatBool(warm), func(t *testing.T) {
				p := &StreamPool{conns: make(map[key]*connection, size)}
				a := &Assembler{connPool: p}
				// Synthetic aliases to one OPEN connection test retention without
				// allocating 64k large connections; this flush cannot remove entries.
				shared := &connection{live: true}
				p.conns[snapshotKey(0)] = shared
				if warm {
					a.FlushWithOptions(FlushOptions{})
				}
				old := a.flushSnapshot
				for i := 1; i < size; i++ {
					p.conns[snapshotKey(i)] = shared
				}
				if len(p.conns) != size {
					t.Fatalf("fixture cardinality = %d, want %d", len(p.conns), size)
				}
				if f, c := a.FlushWithOptions(FlushOptions{}); f != 0 || c != 0 || len(p.conns) != size {
					t.Fatalf("no-op flush = (%d, %d), remaining = %d", f, c, len(p.conns))
				}
				checkSnapshotCleared(t, a)
				if size == maxFlushSnapshotConnections {
					if cap(a.flushSnapshot) != size {
						t.Fatalf("boundary capacity = %d, want %d", cap(a.flushSnapshot), size)
					}
				} else {
					if cap(a.flushSnapshot) != cap(old) {
						t.Fatalf("oversized flush retained capacity %d, want %d", cap(a.flushSnapshot), cap(old))
					}
					if warm && &a.flushSnapshot[:1][0] != &old[:1][0] {
						t.Fatal("oversized flush replaced old small buffer")
					}
				}
			})
		}
	}
}

func TestFlushSnapshotTimestampBoundary(t *testing.T) {
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
				a := &Assembler{connPool: p}
				if f, n := a.FlushWithOptions(FlushOptions{T: tc, TC: tc}); f != 0 || n != 0 {
					t.Fatalf("already-closed flush = (%d, %d)", f, n)
				}
				if removed := p.conns[k] == nil; removed != (delta < 0) {
					t.Fatalf("removed = %v, want %v", removed, delta < 0)
				}
				checkSnapshotCleared(t, a)
			})
		}
	}
	k := snapshotKey(2)
	c := &connection{}
	c.reset(&k, nil, tc.Add(-time.Hour))
	p := &StreamPool{conns: map[key]*connection{k: c}}
	a := &Assembler{connPool: p}
	if f, n := a.FlushWithOptions(FlushOptions{T: tc}); f != 0 || n != 0 {
		t.Fatalf("zero-TC flush = (%d, %d)", f, n)
	}
	if p.conns[k] != c || c.c2s.closed || c.s2c.closed || !c.c2s.lastSeen.Equal(tc.Add(-time.Hour)) || !c.s2c.lastSeen.Equal(tc.Add(-time.Hour)) {
		t.Fatal("zero TC changed idle open connection")
	}
	checkSnapshotCleared(t, a)
}

func TestFlushSnapshotSeparateAssemblers(t *testing.T) {
	p := &StreamPool{conns: make(map[key]*connection)}
	for i := 0; i < 16; i++ {
		p.conns[snapshotKey(i)] = &connection{live: true}
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
		checkSnapshotCleared(t, a)
		if cap(a.flushSnapshot) != 16 {
			t.Fatalf("retained capacity = %d, want 16", cap(a.flushSnapshot))
		}
	}
	if &assemblers[0].flushSnapshot[:16][0] == &assemblers[1].flushSnapshot[:16][0] {
		t.Fatal("assemblers share snapshot storage")
	}
	if len(p.conns) != 16 {
		t.Fatal("simultaneous no-op flush changed membership")
	}
}
