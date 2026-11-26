package dnp3

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func (d *dnp3Reader) frameDatagrams(emit func(*types.DNP3)) {
	var dirs [2]linkAssemblies
	var masters, outstations, ordered []*types.DNP3
	add := func(r *types.DNP3) {
		if r == nil {
			return
		}
		ordered = append(ordered, r)
		if r.IsMaster {
			masters = append(masters, r)
		} else {
			outstations = append(outstations, r)
		}
	}
	for f := range d.conversation.Fragments() {
		at, server := core.FragmentTime(f), core.FromServer(f)
		side := 0
		if server {
			side = 1
		}
		a := &dirs[side]
		for data := f.Raw(); len(data) > 0; {
			if len(data) < linkHeaderLen || data[0] != startByte1 || data[1] != startByte2 || !crcValid(data[:8], data[8:10]) {
				a.flush(0, true, "invalid datagram link header", add)
				add(d.lostRecord(server, at, int64(len(data)), "invalid datagram link header"))
				break
			}
			n := frameLen(data[2])
			if n < 0 || n > len(data) {
				a.flush(0, true, "truncated datagram frame", add)
				add(d.lostRecord(server, at, int64(len(data)), "truncated datagram frame"))
				break
			}
			add(d.assembledFrame(a, data[:n], at, server, false, add))
			data = data[n:]
		}
	}
	for _, a := range dirs {
		a.flush(0, true, "EOF", add)
	}
	correlate(masters, outstations)
	for _, r := range ordered {
		emit(r)
	}
}
