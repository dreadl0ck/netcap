package dnp3

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// Datagrams keeps only DNP3 application assembly when conversation tracking is disabled.
type Datagrams struct{ links linkAssemblies }

func (d *Datagrams) Decode(data []byte, ctx *types.PacketContext, at int64, emit func(*types.DNP3)) {
	r := dnp3Reader{conversation: &core.ConversationInfo{ClientIP: ctx.SrcIP, ClientPort: ctx.SrcPort, ServerIP: ctx.DstIP, ServerPort: ctx.DstPort, CommunityID: ctx.CommunityID}}
	for len(data) > 0 {
		if len(data) < linkHeaderLen || data[0] != startByte1 || data[1] != startByte2 || !crcValid(data[:8], data[8:10]) {
			d.links = nil
			emit(r.lostRecord(false, at, int64(len(data)), "invalid datagram link header"))
			return
		}
		n := frameLen(data[2])
		if n < 0 || n > len(data) {
			d.links = nil
			emit(r.lostRecord(false, at, int64(len(data)), "truncated datagram frame"))
			return
		}
		if m := r.assembledFrame(&d.links, data[:n], at, false, false); m != nil {
			emit(m)
		}
		data = data[n:]
	}
}
