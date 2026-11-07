package dnp3

import (
	"bytes"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

// Link frames never span datagrams. Only the DNP3 transport's FIR/FIN and
// six-bit sequence permit joining CRC-validated user data across frames.
func (d *dnp3Reader) frameDatagrams(emit func(*types.DNP3)) {
	type key struct {
		server   bool
		src, dst int32
	}
	type assembly struct {
		data, last []byte
		seq        byte
		at         int64
	}
	pending := map[key]*assembly{}
	var masters, outstations, ordered []*types.DNP3
	add := func(r *types.DNP3) {
		ordered = append(ordered, r)
		if r.IsMaster {
			masters = append(masters, r)
		} else {
			outstations = append(outstations, r)
		}
	}
	for _, f := range d.conversation.Data {
		at, server := core.FragmentTime(f), core.FromServer(f)
		for k, a := range pending {
			if at-a.at > 30e9 || at < a.at {
				delete(pending, k)
			}
		}
		data := f.Raw()
		for len(data) > 0 {
			if len(data) < linkHeaderLen || data[0] != startByte1 || data[1] != startByte2 || !crcValid(data[:8], data[8:10]) {
				clear(pending)
				add(d.lostRecord(server, at, int64(len(data)), "invalid datagram link header"))
				break
			}
			n := frameLen(data[2])
			if n < 0 || n > len(data) {
				clear(pending)
				add(d.lostRecord(server, at, int64(len(data)), "truncated datagram frame"))
				break
			}
			r, user := d.parseLinkFrame(data[:n], at, server, false)
			data = data[n:]
			k := key{server, r.Source, r.Destination}
			if user == nil {
				delete(pending, k)
				add(r)
				continue
			}
			seq, first, final := user[0]&63, user[0]&64 != 0, user[0]&128 != 0
			r.TransportSeq, r.TransportFIR, r.TransportFIN = int32(seq), first, final
			a := pending[k]
			if a != nil && seq == a.seq && bytes.Equal(a.last, user) {
				continue
			}
			if first {
				delete(pending, k)
				if final {
					d.parseApplicationLayer(r, user)
					add(r)
					continue
				}
				if len(pending) >= 64 {
					r.ParseStatus, r.ParseError = statusLost, "transport assembly limit"
					add(r)
					continue
				}
				a = &assembly{at: at}
				pending[k] = a
			} else if a == nil || seq != (a.seq+1)&63 {
				delete(pending, k)
				r.ParseStatus, r.ParseError = statusLost, "transport sequence gap"
				add(r)
				continue
			}
			if len(a.data)+len(user)-1 > 65535 {
				delete(pending, k)
				r.ParseStatus, r.ParseError = statusLost, "transport assembly limit"
				add(r)
				continue
			}
			a.data = append(a.data, user[1:]...)
			a.seq, a.last = seq, bytes.Clone(user)
			if final {
				d.parseApplicationLayer(r, append([]byte{0xc0 | seq}, a.data...))
				r.Timestamp = a.at
				delete(pending, k)
			} else {
				r.ParseStatus, r.ParseError = statusUnsupported, "transport fragment pending"
			}
			add(r)
		}
	}
	correlate(masters, outstations)
	for _, r := range ordered {
		emit(r)
	}
}
