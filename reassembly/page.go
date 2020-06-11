package reassembly

import (
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"sync"

	"time"
)

const pageBytes = 1900

/* page: implements a byteContainer */

// page is used to store TCP data we're not ready for yet (out-of-order
// packets).  Unused pages are stored in and returned from a pageCache, which
// avoids memory allocation.  Used pages are stored in a doubly-linked list in
// a connection.
type page struct {
	bytes      []byte
	seq        Sequence
	prev, next *page
	buf        [pageBytes]byte
	ac         AssemblerContext // only set for the first page of a packet
	seen       time.Time
	start, end bool
	sync.Mutex
}

func (p *page) getBytes() []byte {
	return p.bytes
}
func (p *page) captureInfo() gopacket.CaptureInfo {
	return p.ac.GetCaptureInfo()
}
func (p *page) assemblerContext() AssemblerContext {
	return p.ac
}
func (p *page) convertToPages(pc *pageCache, skip int, ac AssemblerContext) (*page, *page, int) {
	if skip != 0 {
		p.bytes = p.bytes[skip:]
		p.seq = p.seq.Add(skip)
	}
	p.prev, p.next = nil, nil
	return p, p, 1
}
func (p *page) length() int {
	return len(p.bytes)
}
func (p *page) release(pc *pageCache) int {
	pc.replace(p)
	return 1
}
func (p *page) isStart() bool {
	return p.start
}
func (p *page) isEnd() bool {
	return p.end
}
func (p *page) getSeq() Sequence {
	return p.seq
}
func (p *page) isPacket() bool {
	return p.ac != nil
}
func (p *page) String() string {
	return fmt.Sprintf("page@%p{seq: %v, bytes:%d, -> nextSeq:%v} (prev:%p, next:%p)", p, p.seq, len(p.bytes), p.seq+Sequence(len(p.bytes)), p.prev, p.next)
}
