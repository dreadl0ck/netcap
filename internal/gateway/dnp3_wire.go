package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
)

// IEEE 1815 sizing/CRC follows decoder/stream/dnp3/{framing,crc}. The
// gateway rejects corruption; a passive decoder's resynchronization is unsafe here.
func dnpCRC(b []byte) uint16 {
	var crc uint16
	for _, v := range b {
		crc ^= uint16(v)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

type dnpFrame struct {
	control             byte
	destination, source uint16
	data                []byte
}

func (f dnpFrame) wire() []byte {
	b := []byte{5, 0x64, byte(5 + len(f.data)), f.control, byte(f.destination), byte(f.destination >> 8), byte(f.source), byte(f.source >> 8)}
	b = binary.LittleEndian.AppendUint16(b, dnpCRC(b))
	for off := 0; off < len(f.data); {
		end := min(off+16, len(f.data))
		b = append(b, f.data[off:end]...)
		b = binary.LittleEndian.AppendUint16(b, dnpCRC(f.data[off:end]))
		off = end
	}
	return b
}
func parseDNPFrame(b []byte) (dnpFrame, error) {
	var f dnpFrame
	if len(b) < 10 || b[0] != 5 || b[1] != 0x64 || b[2] < 5 || dnpCRC(b[:8]) != binary.LittleEndian.Uint16(b[8:10]) {
		return f, errFrame
	}
	n := int(b[2]) - 5
	if len(b) != 10+n+2*((n+15)/16) {
		return f, errFrame
	}
	f = dnpFrame{control: b[3], destination: binary.LittleEndian.Uint16(b[4:]), source: binary.LittleEndian.Uint16(b[6:])}
	if f.source >= 0xfffc || f.destination >= 0xfffc || f.source == f.destination {
		return f, errFrame
	}
	for off, left := 10, n; left > 0; {
		size := min(left, 16)
		if dnpCRC(b[off:off+size]) != binary.LittleEndian.Uint16(b[off+size:]) {
			return dnpFrame{}, errFrame
		}
		f.data = append(f.data, b[off:off+size]...)
		off += size + 2
		left -= size
	}
	return f, nil
}
func (g *Gateway) readDNP(ctx context.Context, c net.Conn, idle bool) (dnpFrame, error) {
	var h [10]byte
	wait := g.cfg.IOTimeout
	if idle {
		wait = g.cfg.IdleTimeout
	}
	c.SetReadDeadline(deadline(ctx, wait))
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return dnpFrame{}, err
	}
	c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
	if _, err := io.ReadFull(c, h[1:]); err != nil {
		return dnpFrame{}, err
	}
	if h[0] != 5 || h[1] != 0x64 || h[2] < 5 || dnpCRC(h[:8]) != binary.LittleEndian.Uint16(h[8:]) {
		return dnpFrame{}, errFrame
	}
	n := int(h[2]) - 5
	tail := make([]byte, n+2*((n+15)/16))
	if _, err := io.ReadFull(c, tail); err != nil {
		return dnpFrame{}, err
	}
	return parseDNPFrame(append(h[:], tail...))
}

// Each TCP leg owns its link state. Confirmed link receipt and application
// confirmation acknowledge buffering, never execution. Denial closes both legs.
type dnpLink struct {
	g                  *Gateway
	c                  net.Conn
	master, outstation uint16
	bound              bool
	fromMaster         bool
	reset, expected    bool
	last               []byte
	txTransport        byte
	busy               bool
}

func (l *dnpLink) reply(ctx context.Context, f dnpFrame, code byte) error {
	control := code
	if !l.fromMaster {
		control |= 0x80
	}
	return l.g.writeFrame(ctx, l.c, (dnpFrame{control: control, destination: f.source, source: f.destination}).wire())
}
func (l *dnpLink) next(ctx context.Context, idle bool) (dnpFrame, error) {
	for i := 0; i < l.g.cfg.MaxStateEntries; i++ {
		f, err := l.g.readDNP(ctx, l.c, idle)
		if err != nil {
			return f, err
		}
		master, out := f.source, f.destination
		if !l.fromMaster {
			master, out = f.destination, f.source
		}
		if (f.control&0x80 != 0) != l.fromMaster || f.control&0x40 == 0 {
			return f, errFrame
		}
		if l.bound && (master != l.master || out != l.outstation) {
			return f, errFrame
		}
		l.bound = true
		l.master = master
		l.outstation = out
		switch f.control & 15 {
		case 0, 9:
			if f.control&0x30 != 0 || len(f.data) != 0 {
				return f, errFrame
			}
			code := byte(0)
			if f.control&15 == 0 && l.busy {
				return f, errFrame
			}
			if f.control&15 == 0 {
				l.reset = true
				l.expected = true
				l.last = nil
			} else {
				code = 11
			}
			if l.reply(ctx, f, code) != nil {
				return f, errFrame
			}
			continue
		case 2, 3:
			if !l.reset || f.control&0x10 == 0 {
				return f, errFrame
			}
			bit := f.control&0x20 != 0
			if bit != l.expected {
				if l.last == nil || !bytes.Equal(l.last, f.wire()) {
					return f, errFrame
				}
				if l.reply(ctx, f, 0) != nil {
					return f, errFrame
				}
				continue
			}
			if f.control&15 == 2 && len(f.data) != 0 {
				return f, errFrame
			}
			if f.control&15 == 3 && len(f.data) < 2 {
				return f, errFrame
			}
			l.expected = !l.expected
			l.last = f.wire()
			if l.reply(ctx, f, 0) != nil {
				return f, errFrame
			}
			if f.control&15 == 2 {
				continue
			}
			return f, nil
		case 4:
			if f.control&0x30 != 0 || len(f.data) < 2 {
				return f, errFrame
			}
			return f, nil
		default:
			return f, errFrame
		}
	}
	return dnpFrame{}, errFrame
}
func (l *dnpLink) confirm(ctx context.Context, sequence byte) error {
	control := byte(0x44)
	src, dst := l.outstation, l.master
	if !l.fromMaster {
		control |= 0x80
		src, dst = l.master, l.outstation
	}
	data := []byte{0xc0 | l.txTransport, 0xc0 | sequence, 0}
	l.txTransport = (l.txTransport + 1) & 63
	return l.g.writeFrame(ctx, l.c, (dnpFrame{control: control, destination: dst, source: src, data: data}).wire())
}

type dnpApplication struct {
	control, function byte
	objects           []byte
	frames            []dnpFrame
}

func (l *dnpLink) application(ctx context.Context, idle bool, budget *int, frames *int) (dnpApplication, error) {
	var app dnpApplication
	var data []byte
	var sequence byte
	for {
		f, err := l.next(ctx, idle && len(data) == 0)
		if err != nil {
			return app, err
		}
		l.busy = true
		*frames++
		*budget += len(f.wire())
		if *frames > l.g.cfg.MaxStateEntries || *budget > l.g.cfg.MaxMessageBytes {
			return app, errFrame
		}
		t := f.data[0]
		if len(data) == 0 {
			if t&0x80 == 0 {
				return app, errFrame
			}
		} else if t&0x80 != 0 || t&63 != sequence {
			return app, errFrame
		}
		sequence = (t + 1) & 63
		data = append(data, f.data[1:]...)
		app.frames = append(app.frames, f)
		if t&0x40 != 0 {
			break
		}
	}
	if len(data) < 2 || data[0]&0x10 != 0 {
		return app, errFrame
	} // Unsolicited exchanges are not this profile.
	app.control, app.function = data[0], data[1]
	app.objects = data[2:]
	if !l.fromMaster && app.function == 129 {
		if len(app.objects) < 2 {
			return app, errFrame
		}
		app.objects = app.objects[2:]
	}
	return app, nil
}
func (l *dnpLink) message(ctx context.Context, idle bool) ([]dnpApplication, []byte, error) {
	defer func() { l.busy = false }()
	var apps []dnpApplication
	var objects []byte
	budget, frames := 0, 0
	var function, seq byte
	for {
		app, err := l.application(ctx, idle && len(apps) == 0, &budget, &frames)
		if err != nil {
			return nil, nil, err
		}
		// Requests occupy one application APDU (possibly many transport
		// segments). Never reinterpret multiple requests as one authorization.
		if l.fromMaster && app.control&0xc0 != 0xc0 {
			return nil, nil, errFrame
		}
		if len(apps) == 0 {
			if app.control&0x80 == 0 {
				return nil, nil, errFrame
			}
			function = app.function
		} else if app.control&0x80 != 0 || app.function != function || app.control&15 != seq {
			return nil, nil, errFrame
		}
		seq = (app.control + 1) & 15
		if app.function == 0 {
			return nil, nil, errFrame
		}
		if app.control&0x20 != 0 {
			if l.confirm(ctx, app.control&15) != nil {
				return nil, nil, errFrame
			}
		}
		objects = append(objects, app.objects...)
		apps = append(apps, app)
		if app.control&0x40 != 0 {
			return apps, objects, nil
		}
	}
}
