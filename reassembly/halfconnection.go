package reassembly

import (
	"fmt"
	"time"
)

/* one-way connection, i.e. halfconnection */
type halfconnection struct {

	dir               TCPFlowDirection
	pages             int      // Number of pages used (both in first/last and saved)
	saved             *page    // Doubly-linked list of in-order pages (seq < nextSeq) already given to Stream who told us to keep
	first, last       *page    // Doubly-linked list of out-of-order pages (seq > nextSeq)
	nextSeq           Sequence // sequence number of in-order received bytes
	ackSeq            Sequence
	created, lastSeen time.Time
	stream            Stream
	closed            bool

	// for stats
	queuedBytes    int
	queuedPackets  int
	overlapBytes   int
	overlapPackets int
}

func (half *halfconnection) String() string {
	closed := ""

	if half.closed {
		closed = "closed "
	}

	return fmt.Sprintf("%screated:%v, last:%v", closed, half.created, half.lastSeen)
}

// Dump returns a string (crypticly) describing the halfconnction
func (half *halfconnection) Dump() string {
	s := fmt.Sprintf("pages: %d\n"+
		"nextSeq: %d\n"+
		"ackSeq: %d\n"+
		"Seen :  %s\n"+
		"dir:    %s\n", half.pages, half.nextSeq, half.ackSeq, half.lastSeen, half.dir)
	nb := 0
	for p := half.first; p != nil; p = p.next {
		s += fmt.Sprintf("	Page[%d] %s len: %d\n", nb, p, len(p.bytes))
		nb++
	}
	return s
}
