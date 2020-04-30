package reassembly

import (
	"fmt"
	"sync"
	"time"
)

/* Bi-directionnal connection */

type connection struct {
	key      key // client->server
	c2s, s2c halfconnection
	mu       sync.RWMutex
}

func (c *connection) reset(k key, s Stream, ts time.Time) {
	c.key = k
	base := halfconnection{
		nextSeq:  invalidSequence,
		ackSeq:   invalidSequence,
		created:  ts,
		lastSeen: ts,
		stream:   s,
	}
	c.c2s, c.s2c = base, base
	c.c2s.dir, c.s2c.dir = TCPDirClientToServer, TCPDirServerToClient
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
