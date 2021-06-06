package reassembly

import (
	"github.com/dreadl0ck/gopacket"
	"sync"
)

// Implements a ScatterGather.
type reassemblyObject struct {
	all       []byteContainer
	Skip      int
	Direction TCPFlowDirection
	saved     int
	toKeep    int
	// stats
	queuedBytes    int
	queuedPackets  int
	overlapBytes   int
	overlapPackets int

	sync.Mutex
}

// Lengths returns the lengths for a reassemblyObject.
func (rl *reassemblyObject) Lengths() (int, int) {
	l := 0
	for _, r := range rl.all {
		l += r.length()
	}

	return l, rl.saved
}

// Fetch returns the available data for a reassemblyObject.
func (rl *reassemblyObject) Fetch(l int) []byte {

	if len(rl.all) == 0 {
		return nil
	}
	if l <= rl.all[0].length() {
		return rl.all[0].getBytes()[:l]
	}

	bytes := make([]byte, 0, l)

	for _, bc := range rl.all {
		bytes = append(bytes, bc.getBytes()...)
	}

	return bytes[:l]
}

// KeepFrom will update the toKeep fields value to the supplied offset.
func (rl *reassemblyObject) KeepFrom(offset int) {
	rl.toKeep = offset
}

// CaptureInfo returns the gopacket.CaptureInfo for the supplied offset.
func (rl *reassemblyObject) CaptureInfo(offset int) gopacket.CaptureInfo {
	if offset < 0 {
		return gopacket.CaptureInfo{}
	}

	current := 0
	for _, r := range rl.all {
		if current+r.length() > offset {
			return r.captureInfo()
		}

		current += r.length()
	}

	// Invalid offset
	return gopacket.CaptureInfo{}
}

// Info returns information about the reassemblyObject.
func (rl *reassemblyObject) Info() (TCPFlowDirection, bool, bool, int) {
	if len(rl.all) == 0 {
		return rl.Direction, false, false, rl.Skip
	}
	return rl.Direction, rl.all[0].isStart(), rl.all[len(rl.all)-1].isEnd(), rl.Skip
}

// Stats return the TCPAssemblyStats for the reassemblyObject.
func (rl *reassemblyObject) Stats() TCPAssemblyStats {
	packets := 0

	for _, r := range rl.all {
		if r.isPacket() {
			packets++
		}
	}

	return TCPAssemblyStats{
		Chunks:         len(rl.all),
		Packets:        packets,
		QueuedBytes:    rl.queuedBytes,
		QueuedPackets:  rl.queuedPackets,
		OverlapBytes:   rl.overlapBytes,
		OverlapPackets: rl.overlapPackets,
	}
}
