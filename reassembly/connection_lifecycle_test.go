package reassembly

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type lifecycleFactory func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream

func (f lifecycleFactory) New(n, tcp gopacket.Flow, ac AssemblerContext) Stream {
	return f(n, tcp, ac)
}

type lifecycleStream struct {
	testFactory
	completed  int
	onComplete func() bool
}

func (s *lifecycleStream) ReassemblyComplete(AssemblerContext, gopacket.Flow, string) bool {
	s.completed++
	if s.onComplete != nil {
		return s.onComplete()
	}
	return true
}

func TestConnectionRefRetirementAndReuse(t *testing.T) {
	var streams []*lifecycleStream
	p := NewStreamPool(lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
		s := &lifecycleStream{}
		streams = append(streams, s)
		return s
	}))
	k := snapshotKey(1)
	old, _ := p.getConnection(&k, false, time.Now(), nil)
	rkey := k.reverse()
	lookup, reverse := p.getConnection(&rkey, true, time.Now(), nil)
	snapshot := p.connections(nil)[0]
	if lookup != old || !reverse || snapshot != old || !old.lock() {
		t.Fatal("lookup/snapshot did not capture the current generation")
	}
	if old.conn.mu.TryLock() {
		t.Fatal("reference lock did not retain the connection mutex")
	}
	p.remove(old.conn)
	p.remove(old.conn)
	old.conn.mu.Unlock()
	if len(p.free) != initialAllocSize {
		t.Fatal("duplicate removal added the slot twice")
	}
	if old.lock() {
		old.conn.mu.Unlock()
		t.Fatal("retired reference remains valid")
	}
	current, _ := p.getConnection(&k, false, time.Now(), nil)
	if current.conn != old.conn || current.generation != old.generation+1 {
		t.Fatal("fixture did not reuse the slot with an incremented generation")
	}
	a := NewAssembler(p)
	for _, stale := range []connectionRef{{}, old, lookup, snapshot} {
		if stale.lock() {
			stale.conn.mu.Unlock()
			t.Fatal("stale reference locked a reused slot")
		}
		if a.closeConn(stale) {
			t.Fatal("stale close counted an unprocessed generation")
		}
	}
	if streams[0].completed != 0 || streams[1].completed != 0 || !current.lock() {
		t.Fatal("stale close affected a stream")
	}
	current.conn.mu.Unlock()
	if !a.closeConn(current) || a.closeConn(current) {
		t.Fatal("close must count the current generation only once")
	}
	if streams[1].completed != 1 || len(p.connections(nil)) != 0 {
		t.Fatal("current generation was not completed exactly once")
	}
}

func TestConnectionCallbackDump(t *testing.T) {
	const child = "NETCAP_TEST_CALLBACK_DUMP"
	if os.Getenv(child) != "1" {
		// A deadlocked callback cannot unwind its own connection lock. Kill the
		// isolated test process on timeout instead of leaking a locked goroutine.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestConnectionCallbackDump$", "-test.count=1")
		cmd.Env = append(os.Environ(), child+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("callback diagnostics failed (timeout: %v): %v\n%s", ctx.Err(), err, out)
		}
		return
	}
	p := NewStreamPool(nil)
	s := &lifecycleStream{onComplete: func() bool {
		if got := p.DumpString(); !strings.Contains(got, "<busy connection>") {
			t.Errorf("callback dump lacks busy placeholder: %q", got)
		}
		p.dump()
		return true
	}}
	p.factory = lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream { return s })
	k := snapshotKey(1)
	ref, _ := p.getConnection(&k, false, time.Now(), nil)
	if !NewAssembler(p).closeConn(ref) || s.completed != 1 {
		t.Fatal("diagnostic callback did not complete exactly once")
	}
	if got := ref.String(); got != "<retired connection>" {
		t.Fatalf("retired diagnostic = %q", got)
	}
}

func TestConnectionConcurrentFlushAllCounts(t *testing.T) {
	var streams []*lifecycleStream
	p := NewStreamPool(lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
		s := &lifecycleStream{}
		streams = append(streams, s)
		return s
	}))
	assemblers := []*Assembler{NewAssembler(p), NewAssembler(p)}
	const connections = 8
	for round := 0; round < 50; round++ {
		streams = nil
		for i := 0; i < connections; i++ {
			k := snapshotKey(i)
			p.getConnection(&k, false, time.Now(), nil)
		}
		start, counts := make(chan struct{}), make(chan int, 2)
		for _, a := range assemblers {
			go func(a *Assembler) {
				<-start
				counts <- a.FlushAll()
			}(a)
		}
		close(start)
		if total := <-counts + <-counts; total != connections {
			t.Fatalf("round %d: counted %d closes, want %d", round, total, connections)
		}
		if len(p.connections(nil)) != 0 {
			t.Fatalf("round %d: connections remain", round)
		}
		for _, s := range streams {
			if s.completed != 1 {
				t.Fatalf("round %d: completion callbacks = %d, want 1", round, s.completed)
			}
		}
	}
}

func TestConnectionRetainedCompletionExpiry(t *testing.T) {
	s := &lifecycleStream{onComplete: func() bool { return false }}
	p := NewStreamPool(lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream { return s }))
	a := NewAssembler(p)
	k := snapshotKey(1)
	now := time.Unix(1700000000, 0)
	ref, _ := p.getConnection(&k, false, now, nil)
	if a.FlushAll() != 1 || s.completed != 1 || !ref.lock() {
		t.Fatal("completion returning false did not retain the connection")
	}
	closed := ref.conn.c2s.closed && ref.conn.s2c.closed
	ref.conn.s2c.lastSeen = now.Add(time.Second)
	ref.conn.mu.Unlock()
	if !closed {
		t.Fatal("retained connection halves are not closed")
	}
	boundary := now.Add(time.Second)
	for _, tc := range []time.Time{{}, boundary.Add(-time.Nanosecond), boundary, boundary.Add(time.Nanosecond), boundary.Add(time.Second)} {
		if f, c := a.FlushWithOptions(FlushOptions{T: tc, TC: tc}); f != 0 || c != 0 {
			t.Fatalf("retained expiry reprocessed closed halves: (%d, %d)", f, c)
		}
		wantLive := !tc.After(boundary)
		if live := ref.lock(); live {
			ref.conn.mu.Unlock()
			if !wantLive {
				t.Fatal("expired retained reference remains live")
			}
		} else if wantLive {
			t.Fatal("retained connection expired at or before its latest timestamp")
		}
		if (len(p.connections(nil)) == 1) != wantLive || s.completed != 1 {
			t.Fatal("expiry changed membership incorrectly or repeated completion")
		}
	}
	if a.closeConn(ref) || s.completed != 1 || len(p.free) != initialAllocSize {
		t.Fatal("expired connection was processed or recycled more than once")
	}
}

func TestConnectionRefInvalidAfterReset(t *testing.T) {
	p := NewStreamPool(&testFactoryBench{})
	k := snapshotKey(1)
	ref, _ := p.getConnection(&k, false, time.Now(), nil)
	snapshot := p.connections(nil)
	p.Reset() // No assembler operations are active.
	for _, old := range append(snapshot, ref) {
		if old.lock() {
			old.conn.mu.Unlock()
			t.Fatal("Reset left a live reference")
		}
	}
	if len(p.connections(nil)) != 0 {
		t.Fatal("Reset retained membership")
	}
}

func TestConnectionRemovalChecksMapIdentity(t *testing.T) {
	k := snapshotKey(1)
	old, current := &connection{}, &connection{}
	old.reset(&k, nil, time.Now())
	current.reset(&k, nil, time.Now())
	p := &StreamPool{conns: map[key]*connection{k: current}}
	old.mu.Lock()
	p.remove(old)
	old.mu.Unlock()
	if p.conns[k] != current || len(p.free) != 0 || !current.live {
		t.Fatal("stale pointer removed or recycled the current map occupant")
	}
}

func TestConnectionConcurrentCreation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	p := NewStreamPool(lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &testFactoryBench{}
	}))
	const workers = 32
	refs := make([]connectionRef, workers)
	directions := make([]bool, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range refs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			k := snapshotKey(1)
			if i%2 != 0 {
				k = k.reverse()
			}
			refs[i], directions[i] = p.getConnection(&k, false, time.Now(), nil)
		}(i)
	}
	close(start)
	<-entered
	// Factory callbacks must not hold the pool mutex, even on a cold allocation.
	// Competing lookups may briefly hold read locks before waiting on createMu.
	unlocked := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.mu.TryLock() {
			p.mu.Unlock()
			unlocked = true
			break
		}
		runtime.Gosched()
	}
	serialized := !p.createMu.TryLock()
	if !serialized {
		p.createMu.Unlock()
	}
	close(release)
	wg.Wait()
	if !unlocked || !serialized || calls.Load() != 1 || len(p.connections(nil)) != 1 {
		t.Fatalf("pool unlocked = %v, factory serialized = %v, New calls = %d", unlocked, serialized, calls.Load())
	}
	for i, ref := range refs {
		if ref != refs[0] || directions[i] != (directions[0] != (i%2 != 0)) {
			t.Fatalf("lookup %d disagrees on generation or direction", i)
		}
	}
}

func TestConnectionReuseDoesNotHoldPoolMutex(t *testing.T) {
	entered := make(chan struct{}, 2)
	p := &StreamPool{conns: make(map[key]*connection), nextAlloc: 1,
		factory: lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
			entered <- struct{}{}
			return &testFactoryBench{}
		})}
	k := snapshotKey(1)
	old, _ := p.getConnection(&k, false, time.Now(), nil)
	<-entered
	old.conn.mu.Lock()
	defer old.conn.mu.Unlock()
	p.remove(old.conn)
	result := make(chan connectionRef, 1)
	go func() {
		k := snapshotKey(2)
		ref, _ := p.getConnection(&k, false, time.Now(), nil)
		result <- ref
	}()
	<-entered
	// Wait for reservation, not an arbitrary delay; the retired slot stays locked.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p.mu.TryRLock() {
			reserved := len(p.free) == 0
			p.mu.RUnlock()
			if reserved {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("pool mutex unavailable while reset waits on the retired slot")
		}
		runtime.Gosched()
	}
	if p.createMu.TryLock() {
		p.createMu.Unlock()
		t.Fatal("slot reset was not serialized by createMu")
	}
	old.conn.mu.Unlock()
	select {
	case ref := <-result:
		old.conn.mu.Lock()
		if ref.conn != old.conn || ref.generation != old.generation+1 {
			t.Fatal("creation did not reuse the reserved slot")
		}
	case <-time.After(5 * time.Second):
		old.conn.mu.Lock()
		t.Fatal("creation did not finish after releasing the retired slot")
	}
}

func TestFlushAllProgressMatchesFlushAll(t *testing.T) {
	run := func(progress bool) map[gopacket.Flow][]Reassembly {
		streams := make(map[gopacket.Flow]*lifecycleStream)
		p := NewStreamPool(lifecycleFactory(func(n, _ gopacket.Flow, _ AssemblerContext) Stream {
			s := &lifecycleStream{}
			streams[n] = s
			return s
		}))
		a := NewAssembler(p)
		for i := 0; i < 16; i++ {
			tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: 100, SYN: true}
			ac := &assemblerSimpleContext{Timestamp: time.Unix(1700000000, 0)}
			a.AssembleWithContext(snapshotKey(i)[0], tcp, ac)
			tcp.SYN, tcp.Seq = false, 110
			tcp.BaseLayer.Payload = []byte{byte(i), 42}
			a.AssembleWithContext(snapshotKey(i)[0], tcp, ac)
		}
		closed := 0
		if progress {
			closed = a.FlushAllProgress()
		} else {
			closed = a.FlushAll()
		}
		if closed != 16 || len(p.connections(nil)) != 0 {
			t.Fatalf("closed = %d, remaining = %d", closed, len(p.connections(nil)))
		}
		out := make(map[gopacket.Flow][]Reassembly)
		for n, s := range streams {
			if s.completed != 1 || len(s.reassembly) == 0 {
				t.Fatal("missing data or nonunique completion")
			}
			out[n] = s.reassembly
		}
		return out
	}
	if !reflect.DeepEqual(run(false), run(true)) {
		t.Fatal("progress flush changed reassembly callbacks")
	}
}

func TestConnectionConcurrentAssemblyAndMaintenance(t *testing.T) {
	var streams []*lifecycleStream
	p := NewStreamPool(lifecycleFactory(func(gopacket.Flow, gopacket.Flow, AssemblerContext) Stream {
		s := &lifecycleStream{}
		streams = append(streams, s) // New is serialized by the pool.
		return s
	}))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		a := NewAssembler(p)
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := 0; i < 300; i++ {
				if worker == 3 {
					a.FlushAll()
					a.FlushWithOptions(FlushOptions{T: time.Now(), TC: time.Now()})
					continue
				}
				tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: uint32(i * 10), SYN: true}
				tcp.BaseLayer.Payload = []byte{byte(worker), byte(i)}
				a.AssembleWithContext(snapshotKey(i % 4)[0], tcp, &assemblerSimpleContext{Timestamp: time.Unix(1700000000, 0)})
			}
		}(worker)
	}
	close(start)
	wg.Wait()
	NewAssembler(p).FlushAll()
	if len(streams) == 0 || len(p.connections(nil)) != 0 {
		t.Fatal("stress fixture did not create and drain streams")
	}
	for i, s := range streams {
		if s.completed != 1 {
			t.Fatalf("generation %d completed %d times, want 1", i, s.completed)
		}
	}
}
