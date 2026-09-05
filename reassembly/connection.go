package reassembly

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
)

// Bi-directional TCP network connection.
type connection struct {
	mu         sync.Mutex
	generation uint64
	live       bool
	key        *key // client->server
	c2s, s2c   halfconnection

	ac        assemblerSimpleContext
	firstFlow gopacket.Flow
}

func (c *connection) reset(k *key, s Stream, ts time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation == ^uint64(0) {
		panic("reassembly connection generation exhausted")
	}
	c.generation++
	c.live = true
	c.key = k
	base := halfconnection{
		nextSeq:   invalidSequence,
		ackSeq:    invalidSequence,
		created:   ts,
		lastSeen:  ts,
		stream:    s,
		firstSeen: ts,
	}
	c.c2s, c.s2c = base, base
	c.c2s.dir, c.s2c.dir = TCPDirClientToServer, TCPDirServerToClient
}

// connectionRef identifies one use of a recyclable connection slot.
type connectionRef struct {
	conn       *connection
	generation uint64
}

// lock leaves the connection locked only if this generation is still live.
func (r connectionRef) lock() bool {
	if r.conn == nil {
		return false
	}
	r.conn.mu.Lock()
	if !r.conn.live || r.conn.generation != r.generation {
		r.conn.mu.Unlock()
		return false
	}
	return true
}

// Diagnostics may run inside stream callbacks that already hold conn.mu.
func (r connectionRef) String() string {
	if r.conn == nil {
		return "<nil connection>"
	}
	if !r.conn.mu.TryLock() {
		return "<busy connection>"
	}
	defer r.conn.mu.Unlock()
	if !r.conn.live || r.conn.generation != r.generation {
		return "<retired connection>"
	}
	return fmt.Sprintf("%v %s", r.conn.key, r.conn)
}

func (c *connection) lastSeen() time.Time {
	if c.c2s.lastSeen.Before(c.s2c.lastSeen) {
		return c.s2c.lastSeen
	}

	return c.c2s.lastSeen
}

func (c *connection) String() string {
	return fmt.Sprintf("c2s: %s, s2c: %s", &c.c2s, &c.s2c)
}
