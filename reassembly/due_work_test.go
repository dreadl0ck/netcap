package reassembly

import (
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Scan mechanics from c695d55a, independent of candidate selection. Refresh is
// bookkeeping only: the oracle never uses the heaps to decide what to flush.
func dueScanOracle(a *Assembler, opt FlushOptions) (flushed, closed int) {
	for _, ref := range a.connPool.connections(nil) {
		if !ref.lock() {
			continue
		}
		conn := ref.conn
		for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
			f, c := a.flushClose(conn, half, opt.T, opt.TC)
			if f {
				flushed++
			}
			if c {
				closed++
			}
		}
		if conn.s2c.closed && conn.c2s.closed && conn.s2c.lastSeen.Before(opt.TC) && conn.c2s.lastSeen.Before(opt.TC) {
			a.connPool.remove(conn)
		}
		a.connPool.refreshDueLocked(conn, false)
		conn.mu.Unlock()
	}
	return
}

type dueEvent struct {
	Kind, Bytes, Reason    string
	Direction              TCPFlowDirection
	Start, End, HasContext bool
	Skip, Saved            int
	Context                gopacket.CaptureInfo
	Captures               []gopacket.CaptureInfo
	Flow                   gopacket.Flow
	Seq                    uint32
	Next                   Sequence
}

type dueRecorder struct {
	events       []dueEvent // Callbacks for one flow are serialized by conn.mu.
	keep, retain bool
}

func (s *dueRecorder) Accept(tcp *layers.TCP, dir TCPFlowDirection, next Sequence) bool {
	s.events = append(s.events, dueEvent{Kind: "accept", Direction: dir, Seq: tcp.Seq, Next: next})
	return !tcp.URG
}

func (s *dueRecorder) ReassembledSG(sg ScatterGather, ac AssemblerContext) {
	dir, start, end, skip := sg.Info()
	n, saved := sg.Lengths()
	e := dueEvent{Kind: "data", Bytes: string(sg.Fetch(n)), Direction: dir, Start: start, End: end, Skip: skip, Saved: saved}
	if ac != nil {
		e.HasContext, e.Context = true, ac.GetCaptureInfo()
	}
	for i := 0; i < n; i++ {
		e.Captures = append(e.Captures, sg.CaptureInfo(i))
	}
	s.events = append(s.events, e)
	if s.keep && n > 1 && !end {
		sg.KeepFrom(n - 1)
	}
}

func (s *dueRecorder) ReassemblyComplete(ac AssemblerContext, flow gopacket.Flow, reason string) bool {
	e := dueEvent{Kind: "complete", Flow: flow, Reason: reason}
	if ac != nil {
		e.HasContext, e.Context = true, ac.GetCaptureInfo()
	}
	s.events = append(s.events, e)
	return !s.retain
}

type dueFactory struct {
	mu           sync.Mutex
	streams      map[key][]*dueRecorder
	keep, retain bool
}

func (f *dueFactory) New(net, tcp gopacket.Flow, _ AssemblerContext) Stream {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &dueRecorder{keep: f.keep, retain: f.retain}
	k := key{net, tcp}
	f.streams[k] = append(f.streams[k], s)
	return s
}

func (f *dueFactory) records() map[key][][]dueEvent {
	out := make(map[key][][]dueEvent)
	for k, streams := range f.streams {
		for _, s := range streams {
			out[k] = append(out[k], s.events)
		}
	}
	return out
}

// Called at quiescent operation boundaries, including while a batch is claimed.
func checkDueHeaps(t *testing.T, p *StreamPool) map[key]dueState {
	t.Helper()
	want := make(map[key]dueState)
	eligible := [2]map[*deadlineEntry]bool{make(map[*deadlineEntry]bool), make(map[*deadlineEntry]bool)}
	for _, ref := range p.connections(nil) {
		if !ref.lock() {
			t.Fatal("snapshot contains retired generation")
		}
		c := ref.conn
		state := dueState{}
		for _, h := range []*halfconnection{&c.s2c, &c.c2s} {
			if !h.closed && h.first != nil && (!state.hasPending || h.first.seen.Before(state.pending)) {
				state.pending, state.hasPending = h.first.seen, true
			}
		}
		if c.s2c.closed && c.c2s.closed {
			state.closed, state.hasClosed = c.s2c.lastSeen, true
			if c.c2s.lastSeen.After(state.closed) {
				state.closed = c.c2s.lastSeen
			}
		}
		want[*c.key] = state
		if c.connectionDue == nil {
			if state != (dueState{}) {
				t.Fatal("eligible connection has no index state")
			}
			c.mu.Unlock()
			continue
		}
		if state != c.due {
			t.Fatalf("%v cached due = %+v, want %+v", c.key, c.due, state)
		}
		p.mu.RLock()
		for i, e := range []*deadlineEntry{&c.pendingEntry, &c.closedEntry} {
			present := []bool{state.hasPending, state.hasClosed}[i] && !c.dueClaimed
			if (e.position != 0) != present {
				t.Fatalf("%v heap %d position %d, eligible %v, claimed %v", c.key, i, e.position, present, c.dueClaimed)
			}
			if present {
				eligible[i][e] = true
				if e.ref != ref || !e.deadline.Equal([]time.Time{state.pending, state.closed}[i]) {
					t.Fatalf("%v heap %d stale reference or deadline", c.key, i)
				}
			}
		}
		p.mu.RUnlock()
		c.mu.Unlock()
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	for j, h := range []deadlineHeap{p.pendingDue, p.closedDue} {
		seen := make(map[*deadlineEntry]bool)
		for i, e := range h {
			if e == nil || seen[e] || !eligible[j][e] || e.position != i+1 {
				t.Fatalf("heap %d slot %d duplicate, ineligible, or misplaced entry", j, i)
			}
			seen[e] = true
			if i > 0 && e.deadline.Before(h[(i-1)/2].deadline) {
				t.Fatalf("heap %d slot %d precedes parent", j, i)
			}
		}
		if len(seen) != len(eligible[j]) {
			t.Fatalf("heap %d missing eligible connections", j)
		}
	}
	return want
}

type dueOp struct {
	flow           int
	reverse        bool
	seq            uint32
	flags, payload string
	seen           time.Time
	flush          *FlushOptions
	all            bool
}

func dueTime(n int) time.Time { return time.Time{}.Add(time.Duration(n) * time.Second) }
func duePacket(flow int, reverse bool, seq uint32, flags, payload string, seen int) dueOp {
	return dueOp{flow: flow, reverse: reverse, seq: seq, flags: flags, payload: payload, seen: dueTime(seen)}
}
func dueFlush(t, tc int) dueOp { return dueOp{flush: &FlushOptions{T: dueTime(t), TC: dueTime(tc)}} }

type duePair struct {
	a [2]*Assembler
	f [2]*dueFactory
}

func newDuePair(keep, retain bool, limit int) *duePair {
	p := new(duePair)
	for i := range p.a {
		p.f[i] = &dueFactory{streams: make(map[key][]*dueRecorder), keep: keep, retain: retain}
		p.a[i] = NewAssembler(NewStreamPool(p.f[i]))
		p.a[i].MaxStreamBytes = limit
	}
	return p
}

func (p *duePair) step(t *testing.T, op dueOp) [2]int {
	t.Helper()
	var counts [2][2]int
	for i, a := range p.a {
		switch {
		case op.all:
			counts[i][1] = a.FlushAll()
		case op.flush != nil:
			if i == 0 {
				counts[i][0], counts[i][1] = a.FlushWithOptions(*op.flush)
			} else {
				counts[i][0], counts[i][1] = dueScanOracle(a, *op.flush)
			}
		default:
			net := gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, byte(op.flow + 1)}, []byte{192, 0, 2, 1})
			tcp := &layers.TCP{SrcPort: 12345, DstPort: 80, Seq: op.seq, ACK: true}
			if op.reverse {
				net, tcp.SrcPort, tcp.DstPort = net.Reverse(), tcp.DstPort, tcp.SrcPort
			}
			for _, flag := range op.flags {
				switch flag {
				case 'S':
					tcp.SYN = true
				case 'F':
					tcp.FIN = true
				case 'R':
					tcp.RST = true
				case 'U':
					tcp.URG = true
				}
			}
			// Exercise decoded transport flows and give each twin its own payload.
			tcp.Payload = []byte(op.payload)
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, tcp, gopacket.Payload(tcp.Payload)); err != nil {
				t.Fatal(err)
			}
			decoded := new(layers.TCP)
			if err := decoded.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback); err != nil {
				t.Fatal(err)
			}
			ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: op.seen, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes()), InterfaceIndex: op.flow})
			a.AssembleWithContext(net, decoded, &ctx)
		}
	}
	if counts[0] != counts[1] {
		t.Fatalf("op %+v counts %v != scan %v", op, counts[0], counts[1])
	}
	got, want := checkDueHeaps(t, p.a[0].connPool), checkDueHeaps(t, p.a[1].connPool)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("op %+v membership/deadlines %v != scan %v", op, got, want)
	}
	if !reflect.DeepEqual(p.f[0].records(), p.f[1].records()) {
		t.Fatalf("op %+v callbacks\nheap: %#v\nscan: %#v", op, p.f[0].records(), p.f[1].records())
	}
	return counts[0]
}

func TestDueWorkDifferential(t *testing.T) {
	for seed := int64(0); seed < 12; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			p := newDuePair(seed%3 == 0, seed%2 == 0, []int{0, 24, 256}[seed%3])
			r := rand.New(rand.NewSource(seed))
			for step := 0; step < 250; step++ {
				op := duePacket(r.Intn(8), r.Intn(2) == 0, uint32(100+r.Intn(24)), []string{"", "", "S", "F", "R", "U"}[r.Intn(6)], fmt.Sprintf("%04d", step), r.Intn(17)-8)
				if step%3 == 0 {
					op = dueFlush(r.Intn(19)-9, r.Intn(19)-9)
				}
				p.step(t, op)
			}
			p.step(t, dueOp{all: true})
			p.step(t, dueFlush(100, 100))
		})
	}
}

func TestDueWorkHeadDeadlines(t *testing.T) {
	p := newDuePair(false, true, 0)
	p.step(t, duePacket(0, false, 100, "S", "", -5))
	p.step(t, duePacket(0, false, 110, "", "old", -2))
	p.step(t, duePacket(0, false, 105, "", "new", 5))
	if n := p.step(t, dueFlush(0, 0)); n != [2]int{} {
		t.Fatal("older page behind newer head flushed prematurely")
	}
	p.step(t, duePacket(0, false, 105, "", "NEW", 8)) // Replace head with later timestamp.
	if n := p.step(t, dueFlush(8, 0)); n != [2]int{} {
		t.Fatal("head flushed at equality or retained replaced deadline")
	}
	if n := p.step(t, dueFlush(9, 0)); n != [2]int{1, 0} {
		t.Fatalf("due head and older follower: %v", n)
	}
	p.step(t, duePacket(0, false, 120, "", "abc", -1))
	p.step(t, duePacket(0, false, 123, "F", "def", 20))
	if n := p.step(t, dueFlush(0, -9)); n != [2]int{1, 1} {
		t.Fatalf("contiguous newer FIN not released: %v", n)
	}
	p.step(t, dueOp{all: true})
	p.step(t, dueFlush(0, 21))
}

func TestDueWorkInOrderHasNoIndexState(t *testing.T) {
	p := newDuePair(false, true, 0)
	p.step(t, duePacket(0, false, 100, "S", "abc", 1))
	p.step(t, duePacket(0, false, 104, "", "def", 2))
	for _, a := range p.a {
		for _, ref := range a.connPool.connections(nil) {
			if ref.conn.connectionDue != nil {
				t.Fatal("in-order open connection allocated maintenance state")
			}
		}
	}
}

func TestDueWorkRetainedClosedDeadline(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			p := newDuePair(false, true, 0)
			p.step(t, duePacket(0, false, 100, "SF", "a", -3))
			p.step(t, duePacket(0, true, 100, "SR", "b", -2))
			p.step(t, duePacket(0, reverse, 102, "U", "reject", 5))
			for _, tc := range []int{-4, 0, 4, 5} {
				p.step(t, dueFlush(20, tc))
				if len(p.a[0].connPool.connections(nil)) != 1 {
					t.Fatalf("removed retained connection at TC=%d", tc)
				}
			}
			p.step(t, dueFlush(-20, 6))
			if len(p.a[0].connPool.connections(nil)) != 0 {
				t.Fatal("closed connection not expired")
			}
		})
	}
}

func TestDueWorkKeepAndByteLimit(t *testing.T) {
	p := newDuePair(true, true, 0)
	p.step(t, duePacket(0, false, 100, "S", "abc", -3))
	p.step(t, duePacket(0, false, 104, "", "def", -2))
	saved := false
	for _, streams := range p.f[0].streams {
		for _, e := range streams[0].events {
			saved = saved || e.Kind == "data" && e.Saved == 1 && e.Bytes == "cdef"
		}
	}
	if !saved {
		t.Fatal("KeepFrom fixture did not deliver retained bytes")
	}
	p.step(t, duePacket(0, false, 110, "F", "gap", -1))
	p.step(t, dueFlush(0, 0))
	p.step(t, dueOp{all: true})
	for _, flags := range []string{"", "S"} {
		t.Run("limit/"+flags, func(t *testing.T) {
			p := newDuePair(false, true, 3)
			p.step(t, duePacket(0, false, 100, flags, "abc", -3))
			p.step(t, duePacket(0, true, 100, flags, "def", -2))
			if len(p.a[0].connPool.closedDue) != 1 || len(p.a[0].connPool.pendingDue) != 0 {
				t.Fatal("byte-limit closure did not replace pending eligibility with closed eligibility")
			}
			p.step(t, dueFlush(-10, -2))
			if len(p.a[0].connPool.connections(nil)) != 1 {
				t.Fatal("byte-limited connection removed at equality")
			}
			p.step(t, dueFlush(-10, 0))
			if len(p.a[0].connPool.connections(nil)) != 0 {
				t.Fatal("zero TC did not expire pre-zero closed connection")
			}
		})
	}
}

func TestDueWorkClaimRelease(t *testing.T) {
	p := newDuePair(false, true, 0)
	for flow := 0; flow < 5; flow++ {
		p.step(t, duePacket(flow, false, 110, "", "queued", flow-5))
	}
	a := p.a[0]
	opt := FlushOptions{T: dueTime(1), TC: dueTime(-10)}
	refs := a.connPool.claimDue(nil, opt)
	if len(refs) != 5 {
		t.Fatalf("claimed %d, want 5", len(refs))
	}
	checkDueHeaps(t, a.connPool)
	if again := a.connPool.claimDue(nil, opt); len(again) != 0 {
		t.Fatal("claimed a connection twice")
	}
	// Packet mutation while detached must remain the claim owner's responsibility.
	p.step(t, duePacket(0, false, 109, "", "replacement", 10))
	a.flushDue(refs[0], FlushOptions{T: dueTime(-100), TC: dueTime(-100)})
	checkDueHeaps(t, a.connPool)
	a.releaseDue(refs)
	checkDueHeaps(t, a.connPool)
	for _, ref := range a.connPool.connections(nil) {
		if ref.conn.connectionDue != nil && ref.conn.dueClaimed {
			t.Fatal("release left an outstanding claim")
		}
	}
	for _, ref := range refs {
		if ref != (connectionRef{}) {
			t.Fatal("release retained a batch reference")
		}
	}
	p.step(t, dueFlush(1, -10))
	p.step(t, dueFlush(11, 11))
}
