package reassembly

import "github.com/dreadl0ck/gopacket"

// Implements a ScatterGather
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
}

func (rl *reassemblyObject) Lengths() (int, int) {
	l := 0
	for _, r := range rl.all {
		l += r.length()
	}
	return l, rl.saved
}

func (rl *reassemblyObject) Fetch(l int) []byte {
	if l <= rl.all[0].length() {
		return rl.all[0].getBytes()[:l]
	}
	bytes := make([]byte, 0, l)
	for _, bc := range rl.all {
		bytes = append(bytes, bc.getBytes()...)
	}
	return bytes[:l]
}

func (rl *reassemblyObject) KeepFrom(offset int) {
	rl.toKeep = offset
}

func (rl *reassemblyObject) CaptureInfo(offset int) gopacket.CaptureInfo {
	current := 0
	var r byteContainer
	for _, r = range rl.all {
		if current >= offset {
			return r.captureInfo()
		}
		current += r.length()
	}
	if r != nil && current >= offset {
		return r.captureInfo()
	}
	// Invalid offset
	return gopacket.CaptureInfo{}
}

func (rl *reassemblyObject) Info() (TCPFlowDirection, bool, bool, int) {
	return rl.Direction, rl.all[0].isStart(), rl.all[len(rl.all)-1].isEnd(), rl.Skip
}

func (rl *reassemblyObject) Stats() TCPAssemblyStats {
	packets := int(0)
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
