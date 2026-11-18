package reassembly

import (
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
)

// one-way connection, i.e. halfconnection
// this structure has an optimized field order to avoid excessive padding.
type halfconnection struct {
	flow gopacket.Flow

	created, lastSeen, firstSeen time.Time
	stream                       Stream
	overlapPackets               int

	ackSeq        Sequence
	nextSeq       Sequence // sequence number of in-order received bytes
	first, last   *page    // Doubly-linked list of out-of-order pages (seq > nextSeq)
	saved         *page    // Doubly-linked list of in-order pages (seq < nextSeq) already given to Stream who told us to keep
	pageDeadlines *pageDeadlineHeap

	queuedMin, queuedMax uint32

	overlapBytes int
	pages        int // Number of pages used (both in first/last and saved)

	// for stats
	queuedBytes   int
	queuedPackets int
	closed        bool
	synSeen       bool
	synSeq        uint32
	finSeen       bool
	finPending    bool
	finSeq        Sequence

	// track total bytes reassembled for this halfconnection
	totalBytes int

	dir TCPFlowDirection
}

func (h *halfconnection) noteQueuedSequence(seq Sequence) {
	n := uint32(seq)
	h.queuedMin = min(h.queuedMin, n)
	h.queuedMax = max(h.queuedMax, n)
}

// The bounds can be stale after removals, so they only prove disjointness.
func (h *halfconnection) endsBeforeQueue(end Sequence) bool {
	return h.first != nil && end < Sequence(h.queuedMin) &&
		Sequence(h.queuedMax)-end <= uint32Max/2 &&
		(end >= uint32Max/4 || h.queuedMax <= uint32Max-uint32Max/4)
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
	var s strings.Builder
	s.WriteString(fmt.Sprintf("pages: %d\n"+
		"nextSeq: %d\n"+
		"ackSeq: %d\n"+
		"Seen :  %s\n"+
		"dir:    %s\n", half.pages, half.nextSeq, half.ackSeq, half.lastSeen, half.dir))
	nb := 0
	for p := half.first; p != nil; p = p.next {
		s.WriteString(fmt.Sprintf("	Page[%d] %s len: %d\n", nb, p, len(p.bytes)))
		nb++
	}
	return s.String()
}
