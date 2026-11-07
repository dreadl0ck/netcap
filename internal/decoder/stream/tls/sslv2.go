package tls

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"
)

// SSLv2 length includes padding but excludes the two/three-byte record header.
func sslv2Header(b []byte) (header, length, padding int, ok bool) {
	if len(b) < 2 {
		return
	}
	header, length = 2, int(b[0]&0x7f)<<8|int(b[1])
	if b[0]&0x80 == 0 {
		if len(b) < 3 || b[0]&0x40 != 0 { // security escape is not a plaintext hello
			return 0, 0, 0, false
		}
		header, length, padding = 3, int(b[0]&0x3f)<<8|int(b[1]), int(b[2])
	}
	return header, length, padding, length > padding
}

func sslv2HelloType(b []byte) byte {
	h, n, pad, ok := sslv2Header(b)
	if !ok || len(b) < h+9 {
		return 0
	}
	p := b[h:]
	u16 := func(i int) int { return int(binary.BigEndian.Uint16(p[i : i+2])) }
	switch p[0] {
	case 1:
		v, cs, sid, challenge := u16(1), u16(3), u16(5), u16(7)
		if (v == 2 || v >= 0x300 && v <= 0x303) && cs > 0 && cs%3 == 0 && (sid == 0 || sid == 16) && challenge >= 16 && challenge <= 32 && 9+cs+sid+challenge == n-pad {
			return 1
		}
	case 4:
		if len(p) < 11 {
			return 0
		}
		cert, cs, conn := u16(5), u16(7), u16(9)
		if p[1] <= 1 && (p[2] == 1 || p[2] == 0 && cert == 0) && u16(3) == 2 && cs%3 == 0 && conn >= 16 && conn <= 32 && 11+cert+cs+conn == n-pad {
			return 2
		}
	}
	return 0
}

type sslv2Framer struct {
	reader                            *tlsReader
	dir                               reassembly.TCPFlowDirection
	tls                               *tlsRecordFramer
	handoff                           bool
	offset                            uint64
	buf                               []byte
	ts                                int64
	stopped, initialLossUnknown, seen bool
}

func (f *sslv2Framer) feed(b []byte, ts int64) {
	for len(b) > 0 && !f.stopped {
		if f.handoff && f.tls != nil {
			f.tls.feed(b, ts)
			return
		}
		if len(f.buf) == 0 {
			f.ts = ts
		}
		// Read only the header before allocating a bounded record body.
		want := 3
		if len(f.buf) >= 3 {
			h, n, _, ok := sslv2Header(f.buf)
			if !ok {
				f.stopped = true
				return
			}
			want = h + n
		}
		n := min(want-len(f.buf), len(b))
		f.buf = append(f.buf, b[:n]...)
		f.offset += uint64(n)
		b = b[n:]
		f.seen = true
		h, length, _, ok := sslv2Header(f.buf)
		if !ok || len(f.buf) < h+length {
			if len(f.buf) >= 3 && !ok {
				f.stopped = true
			}
			continue
		}
		if sslv2HelloType(f.buf) == 0 {
			// ClientMasterKey and subsequent ciphertext are not plaintext hellos.
			f.stopped = true
			f.buf = nil
			return
		}
		f.emitHello()
		if f.buf[h] == 1 && binary.BigEndian.Uint16(f.buf[h+1:h+3]) >= 0x300 && f.tls != nil {
			f.handoff = true
			f.tls.offset, f.tls.plaintext, f.tls.initialLossUnknown = f.offset, true, f.initialLossUnknown
		}
		f.buf = nil
	}
}

func (f *sslv2Framer) gap(skipped int, _ int64) {
	if f.handoff && f.tls != nil {
		f.tls.gap(skipped, f.ts)
		return
	}
	if skipped == -1 && !f.seen {
		f.initialLossUnknown = true
		return
	}
	f.stopped, f.buf = true, nil
}

func (f *sslv2Framer) eof() {
	f.buf = nil
	if f.handoff && f.tls != nil {
		f.tls.eof()
	}
}

func sslv2Ciphers(b []byte) []uint32 {
	out := make([]uint32, 0, len(b)/3)
	for len(b) >= 3 {
		out = append(out, uint32(b[0])<<16|uint32(b[1])<<8|uint32(b[2]))
		b = b[3:]
	}
	return out
}

func (f *sslv2Framer) emitHello() {
	h, length, pad, _ := sslv2Header(f.buf)
	p := f.buf[h : h+length-pad]
	c := f.reader.conversation
	status := ""
	if f.initialLossUnknown {
		status = "unknown-initial-stream-loss"
	}
	if f.reader.transportObservation != "" {
		if status != "" {
			status += ","
		}
		status += f.reader.transportObservation + "; endpoint delivery unconfirmed"
	}
	var record proto.Message
	var d *decoder.AbstractDecoder
	switch {
	case p[0] == 1 && f.dir == reassembly.TCPDirClientToServer:
		cs, sid := int(binary.BigEndian.Uint16(p[3:5])), int(binary.BigEndian.Uint16(p[5:7]))
		record = &types.TLSClientHello{HelloFormat: "SSLv2", HandshakeVersion: int32(binary.BigEndian.Uint16(p[1:3])),
			HandshakeType: 1, MessageLen: int32(len(p)), SessionIDLen: uint32(sid), SessionID: append([]byte(nil), p[9+cs:9+cs+sid]...),
			SSLv2CipherSpecs: sslv2Ciphers(p[9 : 9+cs]), SSLv2Challenge: append([]byte(nil), p[9+cs+sid:]...),
			Timestamp: f.ts, SrcIP: c.ClientIP, DstIP: c.ServerIP, SrcPort: c.ClientPort, DstPort: c.ServerPort,
			SrcMAC: c.ClientMAC, DstMAC: c.ServerMAC, CommunityID: c.CommunityID, ReassemblyStatus: status}
		d = ClientHelloDecoder
	case p[0] == 4 && f.dir == reassembly.TCPDirServerToClient:
		cert, cs := int(binary.BigEndian.Uint16(p[5:7])), int(binary.BigEndian.Uint16(p[7:9]))
		record = &types.TLSServerHello{HelloFormat: "SSLv2", Version: 2, SSLv2SessionIDHit: p[1] == 1, SSLv2CertificateType: uint32(p[2]),
			SSLv2CipherSpecs: sslv2Ciphers(p[11+cert : 11+cert+cs]), SSLv2ConnectionID: append([]byte(nil), p[11+cert+cs:]...),
			Timestamp: f.ts, SrcIP: c.ServerIP, DstIP: c.ClientIP, SrcPort: c.ServerPort, DstPort: c.ClientPort,
			SrcMAC: c.ServerMAC, DstMAC: c.ClientMAC, CommunityID: c.CommunityID, ReassemblyStatus: status}
		d = ServerHelloDecoder
		if cert > 0 && p[2] == 1 && Decoder.Writer != nil {
			f.reader.parseCertificate(p[11:11+cert], 0, f.ts, f.dir)
		}
	default:
		return
	}
	if d.Writer != nil {
		if err := d.Writer.Write(record); err != nil {
			tlsLog.Error("writing SSLv2 hello", zap.Error(err))
		} else {
			atomic.AddInt64(&d.NumRecordsWritten, 1)
		}
	}
}
