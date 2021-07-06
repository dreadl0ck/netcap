package reassembly

import (
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
)

const assemblerReturnValueInitialSize = 16

/*
 * Assembler
 */

// defaultAssemblerOptions provides default options for an assembler.
// These options are used by default when calling NewAssembler, so if
// modified before a NewAssembler call they'll affect the resulting Assembler.
//
// Note that the default options can result in ever-increasing memory usage
// unless one of the Flush* methods is called on a regular basis.
var defaultAssemblerOptions = assemblerOptions{
	MaxBufferedPagesPerConnection: 0, // unlimited
	MaxBufferedPagesTotal:         0, // unlimited
}

// assemblerOptions controls the behavior of each assembler.  Modify the
// options of each assembler you create to change their behavior.
type assemblerOptions struct {
	// MaxBufferedPagesTotal is an upper limit on the total number of pages to
	// buffer while waiting for out-of-order packets.  Once this limit is
	// reached, the assembler will degrade to flushing every connection it
	// gets a packet for.  If <= 0, this is ignored.
	MaxBufferedPagesTotal int
	// MaxBufferedPagesPerConnection is an upper limit on the number of pages
	// buffered for a single connection.  Should this limit be reached for a
	// particular connection, the smallest sequence number will be flushed, along
	// with any contiguous data.  If <= 0, this is ignored.
	MaxBufferedPagesPerConnection int
}

// Assembler handles reassembling TCP streams.  It is not safe for
// concurrency... after passing a packet in via the assemble call, the caller
// must wait for that call to return before calling assemble again.  Callers can
// get around this by creating multiple assemblers that share a StreamPool.  In
// that case, each individual stream will still be handled serially (each stream
// has an individual mutex associated with it), however multiple assemblers can
// assemble different connections concurrently.
//
// The Assembler provides (hopefully) fast TCP stream re-assembly for sniffing
// applications written in Go.  The Assembler uses the following methods to be
// as fast as possible, to keep packet processing speedy:
//
// Avoids Lock Contention
//
// Assemblers locks connections, but each connection has an individual lock, and
// rarely will two Assemblers be looking at the same connection.  Assemblers
// lock the StreamPool when looking up connections, but they use Reader
// locks initially, and only force a write lock if they need to create a new
// connection or close one down.  These happen much less frequently than
// individual packet handling.
//
// Each assembler runs in its own goroutine, and the only state shared between
// goroutines is through the StreamPool.  Thus all internal Assembler state
// can be handled without any locking.
//
// NOTE:  If you can guarantee that packets going to a set of Assemblers will
// contain information on different connections per Assembler (for example,
// they're already hashed by PF_RING hashing or some other hashing mechanism),
// then we recommend you use a separate StreamPool per Assembler, thus
// avoiding all lock contention.  Only when different Assemblers could receive
// packets for the same Stream should a StreamPool be shared between them.
//
// Avoids Memory Copying
//
// In the common case, handling of a single TCP packet should result in zero
// memory allocations.  The Assembler will look up the connection, figure out
// that the packet has arrived in order, and immediately pass that packet on to
// the appropriate connection's handling code.  Only if a packet arrives out of
// order is its contents copied and stored in memory for later.
//
// Avoids Memory Allocation
//
// Assemblers try very hard to not use memory allocation unless absolutely
// necessary.  Packet data for sequential packets is passed directly to streams
// with no copying or allocation.  Packet data for out-of-order packets is
// copied into reusable pages, and new pages are only allocated rarely when the
// page cache runs out.  Page caches are Assembler-specific, thus not used
// concurrently and requiring no locking.
//
// Internal representations for connection objects are also reused over time.
// Because of this, the most common memory allocation done by the Assembler is
// generally what's done by the caller in streamFactory.New.  If no allocation
// is done there, then very little allocation is done ever, mostly to handle
// large increases in bandwidth or numbers of connections.
//
// TODO:  The page caches used by an Assembler will grow to the size necessary
// to handle a workload, and currently will never shrink.  This means that
// traffic spikes can result in large memory usage which isn't garbage
// collected when typical traffic levels return.
type Assembler struct {
	sync.Mutex
	assemblerOptions
	ret      []byteContainer
	pc       *pageCache
	connPool *StreamPool
	cacheLP  livePacket
	cacheSG  reassemblyObject
	start    bool
}

// NewAssembler creates a new assembler.  Pass in the StreamPool
// to use, may be shared across assemblers.
//
// This sets some sane defaults for the assembler options,
// see defaultAssemblerOptions for details.
func NewAssembler(pool *StreamPool) *Assembler {
	pool.mu.Lock()
	pool.users++
	pool.mu.Unlock()

	return &Assembler{
		ret:              make([]byteContainer, 0, assemblerReturnValueInitialSize),
		pc:               newPageCache(),
		connPool:         pool,
		assemblerOptions: defaultAssemblerOptions,
	}
}

// Dump returns a short string describing the page usage of the Assembler.
func (a *Assembler) Dump() string {
	s := ""
	s += fmt.Sprintf("pageCache: used: %d, size: %d, free: %d", a.pc.used, a.pc.size, len(a.pc.free))

	return s
}

// AssemblerContext provides method to get metadata.
type AssemblerContext interface {
	GetCaptureInfo() gopacket.CaptureInfo
}

// Implements AssemblerContext for Assemble().
type assemblerSimpleContext gopacket.CaptureInfo

// GetCaptureInfo return the underlying gopacket.CaptureInfo.
func (asc *assemblerSimpleContext) GetCaptureInfo() gopacket.CaptureInfo {
	return gopacket.CaptureInfo(*asc)
}

// assemble calls AssembleWithContext with the current timestamp, useful for
// packets being read directly off the wire.
func (a *Assembler) assemble(netFlow gopacket.Flow, t *layers.TCP) {
	ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Now()})
	a.AssembleWithContext(netFlow, t, &ctx)
}

type assemblerAction struct {
	nextSeq Sequence
	queue   bool
}

// AssembleWithContext reassembles the given TCP packet into its appropriate
// stream.
//
// The timestamp passed in must be the timestamp the packet was seen.
// For packets read off the wire, time.Now() should be fine.  For packets read
// from PCAP files, CaptureInfo.Timestamp should be passed in.  This timestamp
// will affect which streams are flushed by a call to flushCloseOlderThan.
//
// Each AssembleWithContext call results in, in order:
//
//    zero or one call to streamFactory.New, creating a stream
//    zero or one call to ReassembledSG on a single stream
//    zero or one call to ReassemblyComplete on the same stream
func (a *Assembler) AssembleWithContext(netFlow gopacket.Flow, t *layers.TCP, ac AssemblerContext) {
	var (
		conn    *connection
		half    *halfconnection
		rev     *halfconnection
		flowKey = &key{netFlow, t.TransportFlow()}
	)

	// RACE
	a.Lock()
	a.ret = a.ret[:0]
	a.Unlock()

	conn, half, rev = a.connPool.getConnection(flowKey, false, ac.GetCaptureInfo().Timestamp, ac)
	if conn == nil {
		if Debug {
			log.Printf("%v got empty packet on otherwise empty connection", flowKey)
		}

		return
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if half.lastSeen.Before(ac.GetCaptureInfo().Timestamp) {
		half.lastSeen = ac.GetCaptureInfo().Timestamp
	}

	if half.firstSeen.After(ac.GetCaptureInfo().Timestamp) {
		half.firstSeen = ac.GetCaptureInfo().Timestamp
	}
	half.flow = netFlow

	// fmt.Println(netFlow, len(t.Payload), ansi.Yellow, ac.GetCaptureInfo().Timestamp.Format(tf), ansi.Green, half.firstSeen.Format(tf), ansi.Blue, half.lastSeen.Format(tf), ansi.Reset)

	a.start = half.nextSeq == invalidSequence && t.SYN

	if Debug {
		if half.nextSeq < rev.ackSeq {
			log.Printf("Delay detected on %v, data is acked but not assembled yet (acked %v, nextSeq %v)", flowKey, rev.ackSeq, half.nextSeq)
		}
	}

	if !half.stream.Accept(t, half.dir, half.nextSeq) {
		if Debug {
			log.Printf("Ignoring packet")
		}

		return
	}

	if half.closed {
		// this way is closed
		if Debug {
			log.Printf("%v got packet on closed half", flowKey)
		}

		return
	}

	seq, ack, bytes := Sequence(t.Seq), Sequence(t.Ack), t.Payload

	if t.ACK {
		half.ackSeq = ack
	}

	// TODO: push when Ack is seen ??
	action := assemblerAction{
		nextSeq: Sequence(invalidSequence),
		queue:   true,
	}

	a.dump("AssembleWithContext()", half)

	if half.nextSeq == invalidSequence {
		switch {
		case t.SYN:
			if Debug {
				log.Printf("%v saw first SYN packet, returning immediately, seq=%v", flowKey, seq)
			}
			seq = seq.add(1)
			half.nextSeq = seq
			action.queue = false
		case a.start:
			if Debug {
				log.Printf("%v start forced", flowKey)
			}
			half.nextSeq = seq
			action.queue = false
		default:
			if Debug {
				log.Printf("%v waiting for start, storing into connection", flowKey)
			}
		}
	} else {
		diff := half.nextSeq.difference(seq)
		if diff > 0 {
			if Debug {
				log.Printf("%v gap in sequence numbers (%v, %v) diff %v, storing into connection", flowKey, half.nextSeq, seq, diff)
			}
		} else {
			if Debug {
				log.Printf("%v found contiguous data (%v, %v), returning immediately: len:%d", flowKey, seq, half.nextSeq, len(bytes))
			}
			action.queue = false
		}
	}

	action = a.handleBytes(bytes, seq, half, t.SYN, t.RST || t.FIN, action, ac)
	a.Lock()
	l := len(a.ret)
	a.Unlock()
	if l > 0 {
		action.nextSeq = a.sendToConnection(conn, half)
	}

	if action.nextSeq != invalidSequence {
		half.nextSeq = action.nextSeq
		if t.FIN {
			half.nextSeq = half.nextSeq.add(1)
		}
	}

	if Debug {
		log.Printf("%v nextSeq:%d", flowKey, half.nextSeq)
	}
}

// Overlap strategies:
//  - new packet overlaps with sent packets:
//	1) discard new overlapping part
//	2) overwrite old overlapped (TODO)
//  - new packet overlaps existing queued packets:
//	a) consider "age" by timestamp (TODO)
//	b) consider "age" by being present
//	Then
//      1) discard new overlapping part
//      2) overwrite queued part

func (a *Assembler) checkOverlap(half *halfconnection, queue bool, ac AssemblerContext) {
	var (
		next  *page
		cur   = half.last
		bytes = a.cacheLP.bytes
		start = a.cacheLP.seq
		end   = start.add(len(bytes))
	)

	a.dump("before checkOverlap", half)

	//          [s6           :           e6]
	//   [s1:e1][s2:e2] -- [s3:e3] -- [s4:e4][s5:e5]
	//             [s <--ds-- : --de--> e]
	for cur != nil {
		if Debug {
			log.Printf("cur = %p (%s)\n", cur, cur)
		}

		// end < cur.start: continue (5)
		if end.difference(cur.seq) > 0 {
			if Debug {
				log.Printf("case 5\n")
			}

			next = cur
			cur = cur.prev

			continue
		}

		curEnd := cur.seq.add(len(cur.bytes))
		// start > cur.end: stop (1)
		if start.difference(curEnd) <= 0 {
			if Debug {
				log.Printf("case 1\n")
			}
			break
		}

		var (
			diffStart = start.difference(cur.seq)
			diffEnd   = end.difference(curEnd)
		)

		// end > cur.end && start < cur.start: drop (3)
		if diffEnd <= 0 && diffStart >= 0 {
			if Debug {
				log.Printf("case 3\n")
			}

			if cur.isPacket() {
				half.overlapPackets++
			}
			half.overlapBytes += len(cur.bytes)
			// update links
			if cur.prev != nil {
				cur.prev.next = cur.next
			} else {
				half.first = cur.next
			}
			if cur.next != nil {
				cur.next.prev = cur.prev
			} else {
				half.last = cur.prev
			}
			tmp := cur.prev
			half.pages -= cur.release(a.pc)
			cur = tmp
			continue
		}

		// end > cur.end && start < cur.end: drop cur's end (2)
		switch {
		case diffEnd < 0 && start.difference(curEnd) > 0:
			if Debug {
				log.Printf("case 2\n")
			}
			cur.bytes = cur.bytes[:-start.difference(cur.seq)]
		case diffStart > 0 && end.difference(cur.seq) < 0:
			if Debug {
				log.Printf("case 4\n")
			}
			cur.bytes = cur.bytes[-end.difference(cur.seq):]
			cur.seq = cur.seq.add(-end.difference(cur.seq))
			next = cur
		case diffEnd > 0 && diffStart < 0:
			if Debug {
				log.Printf("case 6\n")
			}
			copy(cur.bytes[-diffStart:-diffStart+len(bytes)], bytes)
			bytes = bytes[:0]
		default:
			if Debug {
				log.Printf("no overlap\n")
			}
			next = cur
		}

		cur = cur.prev
	}

	// Split bytes into pages, and insert in queue
	a.cacheLP.bytes = bytes
	a.cacheLP.seq = start
	if len(bytes) > 0 && queue {
		p, p2, numPages := a.cacheLP.convertToPages(a.pc, 0, ac)
		half.queuedPackets++
		half.queuedBytes += len(bytes)
		half.pages += numPages

		if cur != nil {
			if Debug {
				log.Printf("adding %s after %s", p, cur)
			}

			cur.next = p
			p.prev = cur
		} else {
			if Debug {
				log.Printf("adding %s as first", p)
			}
			half.first = p
		}

		if next != nil {
			if Debug {
				log.Printf("setting %s as next of new %s", next, p2)
			}

			p2.next = next
			next.prev = p2
		} else {
			if Debug {
				log.Printf("setting %s as last", p2)
			}
			half.last = p2
		}
	}
	a.dump("After checkOverlap", half)
}

// Warning: this is a low-level dumper, i.e. a.ret or a.cacheSG might
// be strange, but it could be ok.
func (a *Assembler) dump(text string, half *halfconnection) {
	if !Debug {
		return
	}

	log.Printf("%s: dump\n", text)

	if half != nil {
		p := half.first
		if p == nil {
			log.Printf(" * half.first = %p, no chunks queued\n", p)
		} else {
			s := 0
			nb := 0
			log.Printf(" * half.first = %p, queued chunks:", p)
			for p != nil {
				log.Printf("\t%s bytes:\n%s\n", p, hex.Dump(p.bytes))
				s += len(p.bytes)
				nb++
				p = p.next
			}
			log.Printf("\t%d chunks for %d bytes", nb, s)
		}
		log.Printf(" * half.last = %p\n", half.last)
		log.Printf(" * half.saved = %p\n", half.saved)
		p = half.saved
		for p != nil {
			log.Printf("\tseq:%d %s bytes:\n%s\n", p.getSeq(), p, hex.Dump(p.bytes))
			p = p.next
		}
	}

	log.Printf(" * a.ret\n")

	a.Lock()
	for i, r := range a.ret {
		log.Printf("\t%d: %v b:\n%s\n", i, r.captureInfo(), hex.Dump(r.getBytes()))
	}
	a.Unlock()

	log.Printf(" * a.cacheSG.all\n")

	a.cacheSG.Lock()
	for i, r := range a.cacheSG.all {
		log.Printf("\t%d: %v b:\n%s\n", i, r.captureInfo(), hex.Dump(r.getBytes()))
	}
	a.cacheSG.Unlock()
}

func (a *Assembler) overlapExisting(half *halfconnection, start Sequence, bytes []byte) ([]byte, Sequence) {
	if half.nextSeq == invalidSequence {
		// no start yet
		return bytes, start
	}

	diff := start.difference(half.nextSeq)
	if diff == 0 {
		return bytes, start
	}

	var (
		s = 0
		e = len(bytes)
	)

	// TODO: depending on strategy, we might want to shrink half.saved if possible
	if e != 0 {
		if Debug {
			log.Printf("Overlap detected: ignoring current packet's first %d bytes", diff)
		}
		half.overlapPackets++
		half.overlapBytes += diff
	}

	s += diff
	if s >= e {
		// Completely included in sent
		s = e
	}
	bytes = bytes[s:]

	return bytes, half.nextSeq
}

// handleBytes will prepare send or queue the data.
func (a *Assembler) handleBytes(bytes []byte, seq Sequence, half *halfconnection, start bool, end bool, action assemblerAction, ac AssemblerContext) assemblerAction {
	// TODO: remove for production?
	a.cacheLP.bytes = bytes
	a.cacheLP.start = start
	a.cacheLP.end = end
	a.cacheLP.seq = seq
	a.cacheLP.ac = ac

	if action.queue {
		a.checkOverlap(half, true, ac)

		if (a.MaxBufferedPagesPerConnection > 0 && half.pages >= a.MaxBufferedPagesPerConnection) ||
			(a.MaxBufferedPagesTotal > 0 && a.pc.used >= a.MaxBufferedPagesTotal) {
			if Debug {
				log.Printf("hit max buffer size: %+v, %v, %v", a.assemblerOptions, half.pages, a.pc.used)
			}

			action.queue = false

			a.addNextFromConn(half)
		}

		a.dump("handleBytes after queue", half)
	} else {
		a.cacheLP.bytes, a.cacheLP.seq = a.overlapExisting(half, seq, a.cacheLP.bytes)
		a.checkOverlap(half, false, ac)
		if len(a.cacheLP.bytes) != 0 || end || start {
			a.Lock()
			a.ret = append(a.ret, &a.cacheLP)
			a.Unlock()
		}

		a.dump("handleBytes after no queue", half)
	}

	return action
}

func (a *Assembler) setStatsToSG(half *halfconnection) {
	a.cacheSG.queuedBytes = half.queuedBytes
	half.queuedBytes = 0
	a.cacheSG.queuedPackets = half.queuedPackets
	half.queuedPackets = 0
	a.cacheSG.overlapBytes = half.overlapBytes
	half.overlapBytes = 0
	a.cacheSG.overlapPackets = half.overlapPackets
	half.overlapPackets = 0
}

// Build the ScatterGather object, i.e. prepend saved bytes and
// append continuous bytes.
func (a *Assembler) buildSG(half *halfconnection) (bool, Sequence) {
	// find if there are skipped bytes
	skip := -1
	if half.nextSeq != invalidSequence {
		a.Lock()
		if len(a.ret) > 0 {
			s := a.ret[0].getSeq()
			skip = half.nextSeq.difference(s)
		}
		a.Unlock()
	}

	// TODO: this mechanism needs to be refactored in order to fully support concurrent reassembly
	// Prepending saved bytes in combination with appending continuous bytes,
	// leads to potentially flushing combined messages from the client / server to the stream consumers.

	var (
		nextSeq Sequence
		saved   int
	)
	a.Lock()
	l := len(a.ret)
	if l == 0 {
		a.Unlock()
		saved = a.addPending(half, invalidSequence)
		nextSeq = a.addContiguous(half, invalidSequence)
		a.Lock()
	} else {

		s := a.ret[0].getSeq()
		le := a.ret[0].length()
		last := s.add(le)

		// Prepend saved bytes

		updatedSeq := a.ret[0].getSeq()
		a.Unlock()

		// this operation locks
		saved = a.addPending(half, updatedSeq)

		// Append continuous bytes
		// this operation locks
		nextSeq = a.addContiguous(half, last)

		a.Lock()
	}
	a.Unlock()

	a.cacheSG.all = a.ret
	a.cacheSG.Direction = half.dir
	a.cacheSG.Skip = skip
	a.cacheSG.saved = saved
	a.cacheSG.toKeep = -1
	a.setStatsToSG(half)
	a.dump("after buildSG", half)

	var isEnd bool

	a.Lock()
	l = len(a.ret)
	if l == 0 {
		isEnd = true
	} else {
		isEnd = a.ret[l-1].isEnd()
	}
	a.Unlock()

	return isEnd, nextSeq
}

func (a *Assembler) cleanSG(half *halfconnection, ac AssemblerContext) {
	var (
		cur  = 0
		ndx  = 0
		skip = 0
	)

	a.dump("cleanSG(start)", half)

	// Find first page to keep
	if a.cacheSG.toKeep < 0 {
		ndx = len(a.cacheSG.all)
	} else {

		var (
			bc    byteContainer
			found = false
		)

		skip = a.cacheSG.toKeep
		for ndx, bc = range a.cacheSG.all {
			if a.cacheSG.toKeep < cur+bc.length() {
				found = true
				break
			}
			cur += bc.length()
			if skip >= bc.length() {
				skip -= bc.length()
			}
		}
		if !found {
			ndx++
		}
	}
	// Release consumed pages
	for _, r := range a.cacheSG.all[:ndx] {
		if r == half.saved {
			if half.saved.next != nil {
				half.saved.next.prev = nil
			}

			half.saved = half.saved.next
		} else if r == half.first {
			if half.first.next != nil {
				half.first.next.prev = nil
			}
			if half.first == half.last {
				half.first, half.last = nil, nil
			} else {
				half.first = half.first.next
			}
		}

		half.pages -= r.release(a.pc)
	}

	a.dump("after consumed release", half)

	// Keep un-consumed pages
	nbKept := 0
	half.saved = nil

	saved := new(page)

	// TODO: prevent invalid index access
	ndx = len(a.cacheSG.all)
	for _, r := range a.cacheSG.all[ndx:] {
		first, last, nb := r.convertToPages(a.pc, skip, ac)

		if half.saved == nil {
			half.saved = first
		} else {
			saved.next = first
			first.prev = saved
		}

		saved = last
		nbKept += nb
	}
	//if len(a.cacheSG.all) <= ndx {
	//}

	if Debug {
		log.Printf("Remaining %d chunks in SG\n", nbKept)
		log.Printf("%s\n", a.Dump())
		a.dump("after cleanSG()", half)
	}
}

// sendToConnection sends the current values in a.ret to the connection, closing
// the connection if the last thing sent had End set.
func (a *Assembler) sendToConnection(conn *connection, half *halfconnection) Sequence {
	if Debug {
		fmt.Printf("sendToConnection\n")
	}

	end, nextSeq := a.buildSG(half)

	// for debugging
	// for _, b := range a.ret {
	// 	fmt.Println(ansi.Yellow, conn.key.String(), ansi.Blue, b.length(), ansi.Reset, b.assemblerContext().GetCaptureInfo().Timestamp.Format(tf))
	// }

	var ac AssemblerContext

	a.Lock()
	// use the context from the first non empty bytecontainer
	for _, data := range a.ret {
		if data.length() != 0 {
			ac = data.assemblerContext()
			break
		}
	}
	a.Unlock()

	half.stream.ReassembledSG(&a.cacheSG, ac)
	a.cleanSG(half, ac)

	if end {
		a.closeHalfConnection(conn, half, "END signal received (FIN or RST flag)")
	}

	if Debug {
		log.Printf("after sendToConnection: nextSeq: %d\n", nextSeq)
	}

	return nextSeq
}

// addPending will add the pending bytes.
func (a *Assembler) addPending(half *halfconnection, firstSeq Sequence) int {
	if half.saved == nil {
		return 0
	}

	s := 0
	var ret []byteContainer

	for p := half.saved; p != nil; p = p.next {
		if Debug {
			log.Printf("adding pending @%p %s (%s)\n", p, p, hex.EncodeToString(p.bytes))
		}

		ret = append(ret, p)

		s += len(p.bytes)
	}

	if half.saved.seq.add(s) != firstSeq {
		// non-continuous saved: drop them
		var next *page
		for p := half.saved; p != nil; p = next {
			next = p.next
			p.release(a.pc)
		}

		half.saved = nil
		ret = []byteContainer{}
		s = 0
	}

	a.Lock()
	a.ret = append(ret, a.ret...)
	a.Unlock()

	return s
}

// addContiguous adds contiguous byte-sets to a connection.
func (a *Assembler) addContiguous(half *halfconnection, lastSeq Sequence) Sequence {
	firstPage := half.first
	if firstPage == nil {
		if Debug {
			log.Printf("addContiguous(%d): no pages\n", lastSeq)
		}

		return lastSeq
	}

	if lastSeq == invalidSequence {
		lastSeq = firstPage.seq
	}

	for firstPage != nil && lastSeq.difference(firstPage.seq) == 0 {
		if Debug {
			log.Printf("addContiguous: lastSeq: %d, first.seq=%d, page.seq=%d\n", half.nextSeq, half.first.seq, firstPage.seq)
		}

		lastSeq = lastSeq.add(len(firstPage.bytes))
		a.Lock()
		a.ret = append(a.ret, firstPage)
		a.Unlock()
		half.first = firstPage.next

		if half.first == nil {
			half.last = nil
		}

		if firstPage.next != nil {
			firstPage.next.prev = nil
		}

		firstPage = firstPage.next
	}

	return lastSeq
}

// skipFlush skips the first set of bytes we're waiting for and returns the
// first set of bytes we have.  If we have no bytes saved, it closes the
// connection.
func (a *Assembler) skipFlush(conn *connection, half *halfconnection) {
	if Debug {
		log.Printf("skipFlush %v\n", half.nextSeq)
	}
	// Well, it's embarrassing it there is still something in half.saved
	// FIXME: change API to give back saved + new/no packets
	if half.first == nil {
		a.closeHalfConnection(conn, half, "no bytes saved")

		return
	}

	a.Lock()
	a.ret = a.ret[:0]
	a.Unlock()

	a.addNextFromConn(half)

	nextSeq := a.sendToConnection(conn, half)
	if nextSeq != invalidSequence {
		half.nextSeq = nextSeq
	}
}

func (a *Assembler) closeHalfConnection(conn *connection, half *halfconnection, reason string) {
	if Debug {
		log.Printf("%v closing", conn)
	}

	half.closed = true

	for p := half.first; p != nil; p = p.next {
		// FIXME: it should be already empty
		a.pc.replace(p)
		half.pages--
	}

	if conn.s2c.closed && conn.c2s.closed {
		// pass context with timestamp of the first packet seen
		if conn.c2s.firstSeen.Before(conn.s2c.firstSeen) {
			conn.ac.Timestamp = conn.c2s.firstSeen
			conn.firstFlow = conn.c2s.flow
		} else {
			conn.ac.Timestamp = conn.s2c.firstSeen
			conn.firstFlow = conn.s2c.flow
		}

		if half.stream.ReassemblyComplete(&conn.ac, conn.firstFlow, reason) {
			a.connPool.remove(conn)
		}
	}
}

// addNextFromConn pops the first page from a connection off and adds it to the
// return array.
func (a *Assembler) addNextFromConn(conn *halfconnection) {
	if conn.first == nil {
		return
	}

	if Debug {
		log.Printf("   adding from conn (%v, %v) %v (%d)\n", conn.first.seq, conn.nextSeq, conn.nextSeq-conn.first.seq, len(conn.first.bytes))
	}

	a.Lock()
	a.ret = append(a.ret, conn.first)
	a.Unlock()
	conn.first = conn.first.next

	if conn.first != nil {
		conn.first.prev = nil
	} else {
		conn.last = nil
	}
}

// FlushOptions provide options for flushing connections.
type FlushOptions struct {
	T  time.Time // If nonzero, only connections with data older than T are flushed
	TC time.Time // If nonzero, only connections with data older than TC are closed (if no FIN/RST received)
}

// FlushWithOptions finds any streams waiting for packets older than
// the given time T, and pushes through the data they have (IE: tells
// them to stop waiting and skip the data they're waiting for).
//
// It also closes streams older than TC (that can be set to zero, to keep
// long-lived stream alive, but to flush data anyway).
//
// Each Stream maintains a list of zero or more sets of bytes it has received
// out-of-order.  For example, if it has processed up through sequence number
// 10, it might have bytes [15-20), [20-25), [30,50) in its list.  Each set of
// bytes also has the timestamp it was originally viewed.  A flush call will
// look at the smallest subsequent set of bytes, in this case [15-20), and if
// its timestamp is older than the passed-in time, it will push it and all
// contiguous byte-sets out to the Stream's Reassembled function.  In this case,
// it will push [15-20), but also [20-25), since that's contiguous.  It will
// only push [30-50) if its timestamp is also older than the passed-in time,
// otherwise it will wait until the next flushCloseOlderThan to see if bytes
// [25-30) come in.
//
// Returns the number of connections flushed, and of those, the number closed
// because of the flush.
func (a *Assembler) FlushWithOptions(opt FlushOptions) (flushed, closed int) {
	var (
		conns   = a.connPool.connections()
		closes  = 0
		flushes = 0
	)

	for _, conn := range conns {
		remove := false

		conn.mu.Lock()

		for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
			isFlushed, isClosed := a.flushClose(conn, half, opt.T, opt.TC)
			if isFlushed {
				flushes++
			}

			if isClosed {
				closes++
			}
		}

		if conn.s2c.closed && conn.c2s.closed && conn.s2c.lastSeen.Before(opt.TC) && conn.c2s.lastSeen.Before(opt.TC) {
			remove = true
		}
		conn.mu.Unlock()

		if remove {
			a.connPool.remove(conn)
		}
	}

	return flushes, closes
}

// flushCloseOlderThan flushes and closes streams older than given time.
func (a *Assembler) flushCloseOlderThan(t time.Time) (flushed, closed int) {
	return a.FlushWithOptions(FlushOptions{T: t, TC: t})
}

func (a *Assembler) flushClose(conn *connection, half *halfconnection, t time.Time, _ time.Time) (bool, bool) {
	if half.closed {
		return false, false
	}

	flushed, closed := false, false

	for half.first != nil && half.first.seen.Before(t) {
		flushed = true

		a.skipFlush(conn, half)

		if half.closed {
			closed = true

			return flushed, closed
		}
	}

	// TODO: This causes streams being flushed too early when processing packets concurrently and out of order!
	// Close the connection only if both halfs of the connection last seen before tc.
	//if !half.closed && half.first == nil && conn.lastSeen().Before(tc) {
	//	a.closeHalfConnection(conn, half, "both halfs of the connection last seen before tc")
	//
	//	closed = true
	//}

	return flushed, closed
}

// FlushAll flushes all remaining data into all remaining connections and closes
// those connections. It returns the total number of connections flushed/closed
// by the call.
func (a *Assembler) FlushAll() (closed int) {
	conns := a.connPool.connections()
	closed = len(conns)

	// TODO: doing this in parallel would be nice for performance, but causes a crash in the reassembly pkg for some pcaps... debug
	//wg := sync.WaitGroup{}
	for _, conn := range conns {

		//wg.Add(1)
		//go func(conn *connection) {
		a.closeConn(conn)
		//wg.Done()
		//}(conn)
	}

	//wg.Wait()

	return
}

// FlushAllProgress behaves like FlushAll, but displays a progress bar additionally.
func (a *Assembler) FlushAllProgress() (closed int) {
	conns := a.connPool.connections()
	closed = len(conns)

	// create and start new bar
	bar := pb.StartNew(closed)

	// TODO: doing this in parallel would be nice for performance, but causes a crash in the reassembly pkg for some pcaps... debug
	wg := sync.WaitGroup{}

	//fmt.Println("processing", len(conns))

	for _, conn := range conns {

		wg.Add(1)

		go func(co *connection) {
			a.closeConn(co)
			bar.Increment()
			wg.Done()
		}(conn)
	}

	wg.Wait()
	bar.Finish()

	return
}

func (a *Assembler) closeConn(conn *connection) {
	conn.mu.Lock()
	for _, half := range []*halfconnection{&conn.s2c, &conn.c2s} {
		for !half.closed {
			a.skipFlush(conn, half)
		}

		if !half.closed {
			a.closeHalfConnection(conn, half, "force-flushed")
		}
	}
	conn.mu.Unlock()
}
