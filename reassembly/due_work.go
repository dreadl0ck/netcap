package reassembly

import (
	"container/heap"
	"time"
)

type dueState struct {
	pending, closed       time.Time
	hasPending, hasClosed bool
}

type connectionDue struct {
	due          dueState // Protected by conn.mu; skips unchanged publications.
	pendingEntry deadlineEntry
	closedEntry  deadlineEntry
	dueClaimed   bool // Protected by StreamPool.mu.
}

// Heap fields are protected by StreamPool.mu, never read by packet processing.
type deadlineEntry struct {
	ref      connectionRef
	deadline time.Time
	position int // One-based; zero means absent.
}

type deadlineHeap []*deadlineEntry

func (h deadlineHeap) Len() int           { return len(h) }
func (h deadlineHeap) Less(i, j int) bool { return h[i].deadline.Before(h[j].deadline) }
func (h deadlineHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].position, h[j].position = i+1, j+1
}
func (h *deadlineHeap) Push(v any) {
	e := v.(*deadlineEntry)
	*h = append(*h, e)
	e.position = len(*h)
}
func (h *deadlineHeap) Pop() any {
	last := len(*h) - 1
	e := (*h)[last]
	(*h)[last] = nil
	*h = (*h)[:last]
	*e = deadlineEntry{}
	return e
}

func (h *deadlineHeap) remove(e *deadlineEntry) {
	if e.position != 0 {
		heap.Remove(h, e.position-1)
	}
}

func (h *deadlineHeap) update(e *deadlineEntry, ref connectionRef, deadline time.Time, present bool) {
	if !present {
		h.remove(e)
		return
	}
	if e.position == 0 {
		e.ref, e.deadline = ref, deadline
		heap.Push(h, e)
	} else if !e.deadline.Equal(deadline) {
		e.deadline = deadline
		heap.Fix(h, e.position-1)
	}
}

// refreshDueLocked publishes completed mutations while conn.mu is held.
// A claimed generation remains the maintenance caller's responsibility.
func (p *StreamPool) refreshDueLocked(conn *connection, releaseClaim bool) {
	if !conn.live {
		return
	}
	closed := conn.s2c.closed && conn.c2s.closed
	pending := (!conn.s2c.closed && conn.s2c.first != nil) || (!conn.c2s.closed && conn.c2s.first != nil)
	if !pending && !closed && (conn.connectionDue == nil || (!releaseClaim && !conn.due.hasPending && !conn.due.hasClosed)) {
		return
	}
	if conn.connectionDue == nil {
		conn.connectionDue = &connectionDue{}
	}
	state := dueState{}
	for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
		// Closed halves can still contain pointers to recycled pages.
		if !half.closed && half.first != nil && (!state.hasPending || half.first.seen.Before(state.pending)) {
			state.pending, state.hasPending = half.first.seen, true
		}
	}
	if closed {
		state.closed, state.hasClosed = conn.lastSeen(), true
	}
	if state == conn.due && !releaseClaim {
		return
	}
	conn.due = state
	p.mu.Lock()
	if releaseClaim {
		conn.dueClaimed = false
	}
	if !conn.dueClaimed {
		ref := connectionRef{conn: conn, generation: conn.generation}
		p.pendingDue.update(&conn.pendingEntry, ref, state.pending, state.hasPending)
		p.closedDue.update(&conn.closedEntry, ref, state.closed, state.hasClosed)
	}
	p.mu.Unlock()
}

// Heap order lets us prune non-due subtrees without visiting unrelated entries.
func (h deadlineHeap) collectDue(i int, cutoff time.Time, dst []connectionRef) []connectionRef {
	if i >= len(h) || !h[i].deadline.Before(cutoff) {
		return dst
	}
	ref := h[i].ref
	ref.conn.dueClaimed = true
	dst = append(dst, ref)
	dst = h.collectDue(i*2+1, cutoff, dst)
	return h.collectDue(i*2+2, cutoff, dst)
}

// claimDue selects a finite batch under the pool lock. No connection lock or
// callback is entered here; in-flight mutations are rechecked by the borrower.
func (p *StreamPool) claimDue(dst []connectionRef, opt FlushOptions) []connectionRef {
	p.mu.Lock()
	defer p.mu.Unlock()
	dst = dst[:0]
	for _, queue := range []struct {
		heap   *deadlineHeap
		cutoff time.Time
	}{{&p.pendingDue, opt.T}, {&p.closedDue, opt.TC}} {
		start := len(dst)
		dst = queue.heap.collectDue(0, queue.cutoff, dst)
		count := len(dst) - start
		if count == 0 {
			continue
		}
		if count < len(*queue.heap)/8 {
			for _, ref := range dst[start:] {
				p.pendingDue.remove(&ref.conn.pendingEntry)
				p.closedDue.remove(&ref.conn.closedEntry)
			}
			continue
		}
		// Dense expiry is linear in indexed entries, instead of repeated O(log M)
		// removals. This never scans the pool's unindexed connections.
		h := *queue.heap
		n := 0
		for _, entry := range h {
			if entry.ref.conn.dueClaimed {
				*entry = deadlineEntry{}
			} else {
				h[n] = entry
				n++
				entry.position = n
			}
		}
		clear(h[n:])
		*queue.heap = h[:n]
		heap.Init(queue.heap)
	}
	return dst
}

// releaseDue also restores unprocessed claims if a stream callback panics.
func (a *Assembler) releaseDue(refs []connectionRef) {
	for _, ref := range refs {
		if ref.lock() {
			a.connPool.refreshDueLocked(ref.conn, true)
			ref.conn.mu.Unlock()
		}
	}
	clear(refs)
	if cap(refs) <= maxDueBatchConnections {
		a.dueBatch = refs[:0]
	}
}

func (a *Assembler) flushDue(ref connectionRef, opt FlushOptions) (flushed, closed int) {
	if !ref.lock() {
		return 0, 0
	}
	conn := ref.conn
	defer func() {
		a.connPool.refreshDueLocked(conn, true)
		conn.mu.Unlock()
	}()
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
	return flushed, closed
}
