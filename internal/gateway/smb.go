package gateway

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"unicode/utf16"
)

var smbCommands = [...]string{"NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT", "TREE_DISCONNECT", "CREATE", "CLOSE", "FLUSH", "READ", "WRITE", "LOCK", "IOCTL", "CANCEL", "ECHO", "QUERY_DIRECTORY", "CHANGE_NOTIFY", "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"}

type smbPart struct {
	wire       []byte
	command    uint16
	attrs      map[string]string
	data       []byte
	path, file string
	tree       uint32
	session    uint64
}

func smbText(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errFrame
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
		if u[i] == 0 || u[i] >= 0xd800 && u[i] <= 0xdbff && (i+1 == len(u) || binary.LittleEndian.Uint16(b[(i+1)*2:]) < 0xdc00 || binary.LittleEndian.Uint16(b[(i+1)*2:]) > 0xdfff) || u[i] >= 0xdc00 && u[i] <= 0xdfff && (i == 0 || u[i-1] < 0xd800 || u[i-1] > 0xdbff) {
			return "", errFrame
		}
	}
	return string(utf16.Decode(u)), nil
}

// Direct TCP only: SMB1 and SMB3 encryption/compression transforms fail closed.
func (g *Gateway) readSMB(ctx context.Context, c net.Conn) ([]byte, error) {
	c.SetReadDeadline(deadline(ctx, g.cfg.IdleTimeout))
	var h [4]byte
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return nil, err
	}
	c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
	if _, err := io.ReadFull(c, h[1:]); err != nil {
		return nil, err
	}
	n := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if h[0] != 0 || n < 64 || n > g.cfg.MaxMessageBytes {
		return nil, errFrame
	}
	b := make([]byte, n+4)
	copy(b, h[:])
	_, err := io.ReadFull(c, b[4:])
	return b, err
}

func smbParts(b []byte, response bool, limit int) ([]smbPart, error) {
	var out []smbPart
	for off := 4; ; {
		if len(out) >= limit || len(b)-off < 64 {
			return nil, errFrame
		}
		h := b[off:]
		flags := binary.LittleEndian.Uint32(h[16:])
		if string(h[:4]) != "\xfeSMB" || binary.LittleEndian.Uint16(h[4:]) != 64 || (flags&1 != 0) != response || flags&2 != 0 || flags & ^uint32(0x7f) != 0 {
			return nil, errFrame
		}
		next := int(binary.LittleEndian.Uint32(h[20:]))
		if next != 0 {
			if next < 64 || next%8 != 0 || next > len(h)-64 {
				return nil, errFrame
			}
			h = h[:next]
		}
		cmd := binary.LittleEndian.Uint16(h[12:])
		if int(cmd) >= len(smbCommands) {
			return nil, errFrame
		}
		p := smbPart{wire: h, command: cmd, tree: binary.LittleEndian.Uint32(h[36:]), session: binary.LittleEndian.Uint64(h[40:])}
		p.attrs = map[string]string{"smb.command": smbCommands[cmd], "smb.visibility": "plaintext", "smb.signed": strconv.FormatBool(flags&8 != 0), "smb.signature": "relayed-unverified", "smb.tree_id": strconv.FormatUint(uint64(p.tree), 10)}
		if !response {
			if err := p.parse(); err != nil {
				return nil, err
			}
		}
		out = append(out, p)
		if next == 0 {
			return out, nil
		}
		off += next
	}
}

func (p *smbPart) parse() error {
	b := p.wire
	u16 := func(i int) int { return int(binary.LittleEndian.Uint16(b[i:])) }
	u32 := func(i int) int { return int(binary.LittleEndian.Uint32(b[i:])) }
	region := func(off, n, floor int) ([]byte, error) {
		if n == 0 {
			return nil, nil
		}
		if off < floor || off > len(b) || n > len(b)-off {
			return nil, errFrame
		}
		return b[off : off+n], nil
	}
	var size int
	switch p.command {
	case 0:
		size = 36
	case 1:
		size = 25
	case 2, 4, 13:
		size = 4
	case 3:
		size = 9
	case 5:
		size = 57
	case 6:
		size = 24
	case 7:
		size = 24
	case 8, 9:
		size = 49
	case 14:
		size = 33
	case 16:
		size = 41
	default:
		return errFrame // IOCTL, SET_INFO, async, leases and opaque extensions are not gated safely.
	}
	if len(b) < 64+size-size%2 || u16(64) != size {
		return errFrame
	}
	var err error
	switch p.command {
	case 0:
		if u16(66) == 0 || u16(66) > 64 || 100+2*u16(66) > len(b) {
			return errFrame
		}
	case 1:
		_, err = region(u16(76), u16(78), 88) // Authentication stays opaque, outside events.
	case 3:
		var v []byte
		v, err = region(u16(68), u16(70), 72)
		if err == nil {
			p.path, err = smbText(v)
		}
		if p.path == "" {
			return errFrame
		}
		p.attrs["smb.share"] = p.path
	case 5:
		var v []byte
		v, err = region(u16(108), u16(110), 120)
		if err == nil {
			p.path, err = smbText(v)
		}
		// Create contexts can carry durable handles/leases: reject rather than infer state.
		if u32(112) != 0 || u32(116) != 0 {
			return errFrame
		}
		p.attrs["smb.path"] = p.path
		p.attrs["smb.desired_access"] = strconv.Itoa(u32(88))
		p.attrs["smb.create_disposition"] = strconv.Itoa(u32(100))
		p.attrs["smb.create_options"] = strconv.Itoa(u32(104))
	case 6, 7, 8, 9, 14, 16:
		pos := 72
		if p.command == 8 || p.command == 9 {
			pos = 80
		}
		if p.command == 16 {
			pos = 88
		}
		p.file = hex.EncodeToString(b[pos : pos+16])
		p.attrs["smb.file_id"] = p.file
		if p.command == 8 || p.command == 9 {
			p.attrs["smb.length"] = strconv.Itoa(u32(68))
			p.attrs["smb.offset"] = strconv.FormatUint(binary.LittleEndian.Uint64(b[72:]), 10)
			channel, infoOffset := 100, 108
			if p.command == 9 {
				channel, infoOffset = 96, 104
			}
			if u32(channel) != 0 || u16(infoOffset) != 0 || u16(infoOffset+2) != 0 {
				return errFrame
			} // RDMA channels unsupported.
			if p.command == 9 {
				p.data, err = region(u16(66), u32(68), 112)
			}
		}
		if p.command == 14 {
			_, err = region(u16(88), u16(90), 96)
		}
		if p.command == 16 {
			_, err = region(u16(72), u32(76), 104)
		}
	}
	return err
}

// One outstanding compound bounds state and prevents a partially authorized chain.
// Signed requests/responses are forwarded byte-for-byte; denial closes, never forges a signature.
func (g *Gateway) smbClient(ctx context.Context, c net.Conn, ip string) {
	var up net.Conn
	shares := map[string]string{}
	files := map[string]string{}
	key := func(p smbPart) string {
		return strconv.FormatUint(p.session, 10) + ":" + strconv.FormatUint(uint64(p.tree), 10)
	}
	for n := 0; n < g.cfg.MaxSessionMessages; n++ {
		b, err := g.readSMB(ctx, c)
		if err != nil {
			return
		}
		parts, err := smbParts(b, false, g.cfg.MaxStateEntries)
		if err != nil {
			return
		}
		relatedPath := ""
		newState := 0
		for i := range parts {
			p := &parts[i]
			if p.command == 3 || p.command == 5 {
				newState++
				if len(shares)+len(files)+newState > g.cfg.MaxStateEntries {
					return
				}
			}
			if p.command == 8 && int(binary.LittleEndian.Uint32(p.wire[68:])) > g.cfg.MaxMessageBytes-80 {
				return
			}
			related := binary.LittleEndian.Uint32(p.wire[16:])&4 != 0
			if related {
				if i == 0 {
					return
				}
				p.session, p.tree = parts[i-1].session, parts[i-1].tree
			} else {
				relatedPath = ""
			}
			p.attrs["smb.session_id"] = strconv.FormatUint(p.session, 10)
			p.attrs["smb.tree_id"] = strconv.FormatUint(uint64(p.tree), 10)
			if p.command == 5 {
				relatedPath = p.path
			}
			if p.file != "" {
				path, ok := files[key(*p)+":"+p.file]
				if p.file == "ffffffffffffffffffffffffffffffff" && binary.LittleEndian.Uint32(p.wire[16:])&4 != 0 && relatedPath != "" {
					path, ok = relatedPath, true
				}
				if !ok {
					return
				}
				p.attrs["smb.path"] = path
			}
			if p.command != 3 {
				p.attrs["smb.share"] = shares[key(*p)]
				if p.command == 5 || p.file != "" {
					if p.attrs["smb.share"] == "" {
						return
					}
				}
			}
			e := event("smb", smbCommands[p.command], ip, p.attrs)
			if p.command == 9 {
				e.Body = string(p.data)
			}
			if !g.allowed(e) {
				return
			}
		}
		if up == nil {
			up, err = g.dial(ctx)
			if err != nil {
				return
			}
			defer up.Close()
			stop := context.AfterFunc(ctx, func() { up.Close() })
			defer stop()
		}
		if g.writeFrame(ctx, up, b) != nil {
			return
		}
		reply, err := g.readSMB(ctx, up)
		if err != nil {
			return
		}
		rp, err := smbParts(reply, true, g.cfg.MaxStateEntries)
		if err != nil || len(rp) != len(parts) {
			return
		}
		for i, r := range rp {
			p := parts[i]
			if r.command != p.command || binary.LittleEndian.Uint64(r.wire[24:]) != binary.LittleEndian.Uint64(p.wire[24:]) {
				return
			}
			if binary.LittleEndian.Uint32(r.wire[8:]) != 0 {
				continue
			}
			e := event("smb", smbCommands[p.command], ip, p.attrs)
			e.Phase = "response"
			if p.command == 8 {
				if len(r.wire) < 80 || binary.LittleEndian.Uint16(r.wire[64:]) != 17 {
					return
				}
				off, n := int(r.wire[66]), int(binary.LittleEndian.Uint32(r.wire[68:]))
				if off < 80 || off > len(r.wire) || n > len(r.wire)-off {
					return
				}
				e.Body = string(r.wire[off : off+n])
			}
			if !g.allowed(e) {
				return
			}
			switch p.command {
			case 3:
				shares[key(r)] = p.path
			case 5:
				if len(r.wire) < 152 || binary.LittleEndian.Uint16(r.wire[64:]) != 89 {
					return
				}
				files[key(r)+":"+hex.EncodeToString(r.wire[128:144])] = p.path
			case 6:
				delete(files, key(p)+":"+p.file)
			}
			if len(shares)+len(files) > g.cfg.MaxStateEntries {
				return
			}
		}
		if g.writeFrame(ctx, c, reply) != nil {
			return
		}
		for _, p := range parts {
			if p.command == 2 || p.command == 4 {
				return
			}
		}
	}
}
