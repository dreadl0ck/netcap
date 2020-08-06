package reassembly

import (
	"fmt"
	"time"

	"github.com/dreadl0ck/gopacket"
)

// one-way connection, i.e. halfconnection
// this structure has an optimized field order to avoid excessive padding.
type halfconnection struct {
	flow gopacket.Flow

	created, lastSeen, firstSeen time.Time
	stream                       Stream
	overlapPackets               int

	ackSeq      Sequence
	nextSeq     Sequence // sequence number of in-order received bytes
	first, last *page    // Doubly-linked list of out-of-order pages (seq > nextSeq)
	saved       *page    // Doubly-linked list of in-order pages (seq < nextSeq) already given to Stream who told us to keep

	overlapBytes int
	pages        int // Number of pages used (both in first/last and saved)

	// for stats
	queuedBytes   int
	queuedPackets int
	closed        bool

	dir TCPFlowDirection
}

func (half *halfconnection) String() string {
	closed := ""

	if half.closed {
		closed = "closed "
	}

	return fmt.Sprintf("%screated:%v, last:%v", closed, half.created, half.lastSeen)
}

// Dump returns a string (crypticly) describing the halfconnction.
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
