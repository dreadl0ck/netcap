package tls

import (
	"bufio"
	"bytes"
	"crypto/sha1" // RFC 6455 handshake, not a signature.
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/bacnetip"
	"github.com/dreadl0ck/netcap/internal/tlsdecrypt"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func scEnabled() bool {
	return config.Instance != nil && config.Instance.PacketBACnet && bacnetip.Decoder.Writer != nil && !config.Instance.TLSSecrets.Empty()
}

// A cursor reads authenticated plaintext in TLS stream order, which may differ from timestamp order.
type scCursor struct {
	records []tlsdecrypt.Plaintext
	client  bool
	part    []byte
	at      int64
}

func (c *scCursor) ready() bool {
	for len(c.part) == 0 && len(c.records) > 0 {
		p := c.records[0]
		c.records = c.records[1:]
		if p.Client == c.client {
			c.part, c.at = p.Data, p.At
		}
	}
	return len(c.part) > 0
}
func (c *scCursor) Read(b []byte) (int, error) {
	if !c.ready() {
		return 0, io.EOF
	}
	n := copy(b, c.part)
	c.part = c.part[n:]
	return n, nil
}
func (c *scCursor) header() []byte {
	var h []byte
	for len(h) < 16384 && c.ready() {
		h = append(h, c.part[0])
		c.part = c.part[1:]
		if bytes.HasSuffix(h, []byte("\r\n\r\n")) {
			return h
		}
	}
	return nil
}
func wsToken(h http.Header, name, want string, fold bool) bool {
	for _, v := range h.Values(name) {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s == want || fold && strings.EqualFold(s, want) {
				return true
			}
		}
	}
	return false
}
func scUpgrade(client, server *scCursor) bool {
	h := client.header()
	if !bytes.HasPrefix(h, []byte("GET ")) {
		return false
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(h)))
	if err != nil || req.Proto != "HTTP/1.1" || req.Host == "" || req.ContentLength != 0 || len(req.TransferEncoding) != 0 || !wsToken(req.Header, "Connection", "Upgrade", true) || !wsToken(req.Header, "Upgrade", "websocket", true) || req.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 16 {
		return false
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	res, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(server.header())), req)
	if err != nil || res.StatusCode != 101 || res.Proto != "HTTP/1.1" || !wsToken(res.Header, "Upgrade", "websocket", true) || !wsToken(res.Header, "Connection", "upgrade", true) || res.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) || res.Header.Get("Sec-WebSocket-Extensions") != "" {
		return false
	}
	protocol := res.Header.Get("Sec-WebSocket-Protocol")
	return len(res.Header.Values("Sec-WebSocket-Protocol")) == 1 && (protocol == "hub.bsc.bacnet.org" || protocol == "dc.bsc.bacnet.org") && wsToken(req.Header, "Sec-WebSocket-Protocol", protocol, false)
}

func decodeSecureConnect(c *core.ConversationInfo, records []tlsdecrypt.Plaintext) {
	if !c.TLSDecrypted {
		return
	}
	a, b := scCursor{records: records, client: true}, scCursor{records: records}
	if !scUpgrade(&a, &b) {
		return
	}
	for _, cur := range []*scCursor{&a, &b} {
		ctx := &types.PacketContext{SrcIP: c.ClientIP, DstIP: c.ServerIP, SrcPort: c.ClientPort, DstPort: c.ServerPort, NetworkScope: c.NetworkScope, CommunityID: c.CommunityID}
		if !cur.client {
			ctx.SrcIP, ctx.DstIP = ctx.DstIP, ctx.SrcIP
			ctx.SrcPort, ctx.DstPort = ctx.DstPort, ctx.SrcPort
		}
		var join bacnetip.Assembly
		emit := func(r *types.BACnetIP) {
			if c.FragmentError != nil {
				return
			}
			if err := bacnetip.Decoder.Writer.Write(r); err != nil {
				c.FragmentError = err
			} else {
				atomic.AddInt64(&bacnetip.Decoder.NumRecordsWritten, 1)
			}
		}
		cur.messages(func(body []byte, at int64) {
			join.Advance(at, emit)
			p := gopacket.NewPacket(body, layers.LayerTypeBACnetSC, gopacket.NoCopy)
			if r := join.Decode(p, "session", "BACnet/SC", ctx, at, config.Instance.IncludePayloads); r != nil {
				emit(r)
			}
		}, func(why string, at int64) {
			emit(&types.BACnetIP{Timestamp: at, Carrier: "BACnet/SC", NetworkScope: ctx.NetworkScope, CommunityID: ctx.CommunityID, SrcIP: ctx.SrcIP, DstIP: ctx.DstIP, SrcPort: ctx.SrcPort, DstPort: ctx.DstPort, Assembly: &types.OTAssembly{Status: "incomplete", Reason: why, FirstTimestamp: at}})
		})
		join.Flush(0, true, emit)
	}
}

func (c *scCursor) messages(emit func([]byte, int64), incomplete func(string, int64)) {
	var message []byte
	var start int64
	open := false
	const limit = 1 << 20
	for c.ready() {
		at := c.at
		if !open {
			start = at
		}
		var h [8]byte
		if _, err := io.ReadFull(c, h[:2]); err != nil {
			incomplete("short WebSocket header", start)
			return
		}
		fin, op, masked := h[0]&128 != 0, h[0]&15, h[1]&128 != 0
		if h[0]&0x70 != 0 || masked != c.client {
			incomplete("unsupported WebSocket framing", start)
			return
		}
		n := uint64(h[1] & 127)
		switch n {
		case 126:
			if _, err := io.ReadFull(c, h[:2]); err != nil {
				incomplete("short WebSocket length", start)
				return
			}
			n = uint64(binary.BigEndian.Uint16(h[:]))
			if n < 126 {
				incomplete("invalid WebSocket length", start)
				return
			}
		case 127:
			if _, err := io.ReadFull(c, h[:]); err != nil {
				incomplete("short WebSocket length", start)
				return
			}
			n = binary.BigEndian.Uint64(h[:])
			if n <= 65535 {
				incomplete("invalid WebSocket length", start)
				return
			}
		}
		control := op >= 8
		if control && (!fin || n > 125 || op > 10) || !control && (op != 2 && op != 0 || open != (op == 0)) {
			incomplete("unexpected WebSocket frame", start)
			return
		}
		if !control && n > uint64(limit-len(message)) {
			incomplete("WebSocket message limit", start)
			return
		}
		if masked {
			if _, err := io.ReadFull(c, h[:4]); err != nil {
				incomplete("short WebSocket mask", start)
				return
			}
		}
		if control {
			if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
				incomplete("short WebSocket control", start)
				return
			}
			if op == 8 {
				if open {
					incomplete("close during message", start)
				}
				return
			}
			continue
		}
		off := len(message)
		message = append(message, make([]byte, int(n))...)
		if _, err := io.ReadFull(c, message[off:]); err != nil {
			incomplete("short WebSocket data", start)
			return
		}
		if masked {
			for i := off; i < len(message); i++ {
				message[i] ^= h[(i-off)%4]
			}
		}
		open = !fin
		if fin {
			emit(message, start)
			message = nil
		}
	}
	if open {
		incomplete("EOF during message", start)
	}
}
