package reassembly

import "github.com/dreadl0ck/gopacket"

/* livePacket: implements a byteContainer */
type livePacket struct {
	bytes []byte
	start bool
	end   bool
	ac    AssemblerContext
	seq   Sequence
}

func (lp *livePacket) getBytes() []byte {
	return lp.bytes
}

func (lp *livePacket) captureInfo() gopacket.CaptureInfo {
	return lp.ac.GetCaptureInfo()
}

func (lp *livePacket) assemblerContext() AssemblerContext {
	return lp.ac
}

func (lp *livePacket) length() int {
	return len(lp.bytes)
}

func (lp *livePacket) isStart() bool {
	return lp.start
}

func (lp *livePacket) isEnd() bool {
	return lp.end
}

func (lp *livePacket) getSeq() Sequence {
	return lp.seq
}

func (lp *livePacket) isPacket() bool {
	return true
}

// Creates a page (or set of pages) from a TCP packet: returns the first and last
// page in its doubly-linked list of new pages.
func (lp *livePacket) convertToPages(pc *pageCache, skip int, ac AssemblerContext) (*page, *page, int) {
	ts := lp.captureInfo().Timestamp
	first := pc.next(ts)
	current := first
	current.prev = nil
	first.ac = ac
	numPages := 1
	seq, bytes := lp.seq.add(skip), lp.bytes[skip:]
	for {
		length := min(len(bytes), pageBytes)
		current.bytes = current.buf[:length]
		copy(current.bytes, bytes)
		current.seq = seq
		bytes = bytes[length:]
		if len(bytes) == 0 {
			current.end = lp.isEnd()
			current.next = nil
			break
		}
		seq = seq.add(length)
		current.next = pc.next(ts)
		current.next.prev = current
		current = current.next
		current.ac = nil
		numPages++
	}
	return first, current, numPages
}

func (lp *livePacket) estimateNumberOfPages() int {
	return (len(lp.bytes) + pageBytes + 1) / pageBytes
}

func (lp *livePacket) release(*pageCache) int {
	return 0
}
