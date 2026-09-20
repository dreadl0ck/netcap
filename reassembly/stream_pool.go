package reassembly

import (
	"bytes"
	"fmt"
	"log"
	"sync"
	"time"
)

/*
 * StreamPool
 */

// StreamPool stores all streams created by Assemblers, allowing multiple
// assemblers to work together on stream processing while enforcing the fact
// that a single stream receives its data serially.  It is safe
// for concurrency, usable by multiple Assemblers at once.
//
// StreamPool handles the creation and storage of Stream objects used by one or
// more Assembler objects.  When a new TCP stream is found by an Assembler, it
// creates an associated Stream by calling its streamFactory's New method.
// Thereafter (until the stream is closed), that Stream object will receive
// assembled TCP data via Assembler's calls to the stream's Reassembled
// function.
//
// Like the Assembler, StreamPool attempts to minimize allocation.  Unlike the
// Assembler, though, it does have to do some locking to make sure that the
// connection objects it stores are accessible to multiple Assemblers.
type StreamPool struct {
	conns              map[key]*connection
	users              int
	mu                 sync.RWMutex
	createMu           sync.Mutex
	factory            streamFactory
	free               []*connection
	all                [][]connection
	nextAlloc          int
	newConnectionCount int64
	pendingDue         deadlineHeap
	closedDue          deadlineHeap
}

func (p *StreamPool) grow() {
	conns := make([]connection, p.nextAlloc)
	p.all = append(p.all, conns)
	for i := range conns {
		p.free = append(p.free, &conns[i])
	}
	if Debug {
		log.Println("StreamPool: created", p.nextAlloc, "new connections")
	}
	p.nextAlloc *= 2
}

// dump logs all connections.
func (p *StreamPool) dump() {
	conns := p.connections(nil)
	log.Printf("Remaining %d connections: ", len(conns))
	for _, ref := range conns {
		log.Print(ref)
	}
}

// DumpString logs all connections and returns a string.
func (p *StreamPool) DumpString() string {
	conns := p.connections(nil)
	var b bytes.Buffer

	b.WriteString(fmt.Sprintf("Remaining %d connections: \n", len(conns)))
	for _, ref := range conns {
		b.WriteString(ref.String())
		b.WriteByte('\n')
	}

	return b.String()
}

// remove requires conn.mu. Reuse waits for that lock without holding p.mu.
func (p *StreamPool) remove(conn *connection) {
	p.mu.Lock()
	if conn.live && p.conns[*conn.key] == conn {
		if conn.connectionDue != nil {
			p.pendingDue.remove(&conn.pendingEntry)
			p.closedDue.remove(&conn.closedEntry)
			conn.dueClaimed = false
		}
		conn.live = false
		delete(p.conns, *conn.key)
		p.free = append(p.free, conn)
	}
	p.mu.Unlock()
}

// Reset clears all internal state and releases backing arrays.
// All assembler operations must have stopped before calling Reset.
// This should be called when the pool is no longer needed to allow
// garbage collection of the underlying connection arrays.
// CRITICAL for preventing memory leaks in multi-file processing.
func (p *StreamPool) Reset() {
	p.createMu.Lock()
	defer p.createMu.Unlock()
	for _, ref := range p.connections(nil) {
		if ref.lock() {
			ref.conn.live = false
			ref.conn.mu.Unlock()
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear connections map
	p.conns = make(map[key]*connection, initialAllocSize)
	p.pendingDue, p.closedDue = nil, nil

	// Clear free list
	p.free = make([]*connection, 0, initialAllocSize)

	// CRITICAL: Clear the backing arrays by nil'ing references
	// The p.all slice stores backing arrays for all connection objects
	// and grows unbounded. We must explicitly nil these to allow GC.
	for i := range p.all {
		p.all[i] = nil
	}
	p.all = nil

	// Reset allocation counter to initial size
	p.nextAlloc = initialAllocSize
	p.newConnectionCount = 0

	if Debug {
		log.Println("StreamPool: reset complete, all backing arrays released")
	}
}

// NewStreamPool creates a new connection pool.  Streams will
// be created as necessary using the passed-in streamFactory.
func NewStreamPool(factory streamFactory) *StreamPool {
	return &StreamPool{
		conns:     make(map[key]*connection, initialAllocSize),
		free:      make([]*connection, 0, initialAllocSize),
		factory:   factory,
		nextAlloc: initialAllocSize,
	}
}

func (p *StreamPool) connections(dst []connectionRef) []connectionRef {
	p.mu.RLock()

	conns := dst[:0]
	if cap(conns) < len(p.conns) {
		conns = make([]connectionRef, 0, len(p.conns))
	}

	for _, conn := range p.conns {
		conns = append(conns, connectionRef{conn: conn, generation: conn.generation})
	}

	p.mu.RUnlock()

	return conns
}

// newConnection is called with createMu held, but never p.mu.
func (p *StreamPool) newConnection(k *key, s Stream, ts time.Time) *connection {
	p.mu.Lock()
	if Debug {
		p.newConnectionCount++
		if p.newConnectionCount&0x7FFF == 0 {
			log.Println("StreamPool:", p.newConnectionCount, "requests,", len(p.conns), "used,", len(p.free), "free")
		}
	}

	if len(p.free) == 0 {
		p.grow()
	}

	index := len(p.free) - 1
	c := p.free[index]
	p.free[index] = nil
	p.free = p.free[:index]
	p.mu.Unlock()
	c.reset(k, s, ts)

	return c
}

// lookup requires p.mu. Direction is usable only after validating the reference.
func (p *StreamPool) lookup(k *key) (connectionRef, bool) {
	conn := p.conns[*k]
	if conn != nil {
		return connectionRef{conn: conn, generation: conn.generation}, false
	}

	rk := k.reverse()
	conn = p.conns[rk]

	if conn != nil {
		return connectionRef{conn: conn, generation: conn.generation}, true
	}

	return connectionRef{}, false
}

// getConnection returns a generation reference and its reverse-direction flag.
// With end set, a missing connection returns a zero reference without creation.
func (p *StreamPool) getConnection(k *key, end bool, ts time.Time, ac AssemblerContext) (connectionRef, bool) {
	p.mu.RLock()
	ref, reverse := p.lookup(k)
	p.mu.RUnlock()
	if end || ref.conn != nil {
		return ref, reverse
	}

	// Preserve single factory creation per flow without blocking pool lookups
	// or removals while a retired slot waits for its previous holder to exit.
	p.createMu.Lock()
	defer p.createMu.Unlock()
	p.mu.RLock()
	ref, reverse = p.lookup(k)
	p.mu.RUnlock()
	if ref.conn != nil {
		return ref, reverse
	}

	s := p.factory.New(k[0], k[1], ac)
	conn := p.newConnection(k, s, ts)
	p.mu.Lock()
	p.conns[*k] = conn
	ref = connectionRef{conn: conn, generation: conn.generation}
	p.mu.Unlock()
	return ref, false
}
