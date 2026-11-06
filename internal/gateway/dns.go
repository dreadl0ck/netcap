package gateway

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/dreadl0ck/netcap/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

const maxDNSQuery = 512

var errDNS = errors.New("gateway: invalid or unsupported DNS message")

// ServePacket owns pc. Only single-question IN queries with no resource sections
// are supported (classic DNS, no EDNS, UPDATE, transfers or TCP fallback).
func (g *Gateway) ServePacket(ctx context.Context, pc net.PacketConn) error {
	defer pc.Close()
	if g.cfg.Protocol != "dns" {
		return protocolError(g.cfg.Protocol)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	slots := make(chan struct{}, g.cfg.MaxConnections)
	buf := make([]byte, maxDNSQuery+1)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ip, ok := g.clientAllowed(addr)
		if !ok || n > maxDNSQuery {
			continue
		}
		// Validate before consuming worker slots or creating an upstream socket.
		meta, err := parseDNSQuery(buf[:n])
		if err != nil {
			continue
		}
		select {
		case slots <- struct{}{}:
			req := append([]byte(nil), buf[:n]...)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				resp := g.dnsQuery(ctx, req, meta, ip)
				if ctx.Err() == nil && len(resp) > 0 {
					_ = pc.SetWriteDeadline(deadline(ctx, g.cfg.IOTimeout))
					_, _ = pc.WriteTo(resp, addr)
				}
			}()
		default:
			// UDP overload is dropped rather than spawning unbounded waiters.
		}
	}
}

func (g *Gateway) dnsQuery(parent context.Context, req []byte, meta policy.DNSEvent, ip string) []byte {
	ctx, cancel := context.WithTimeout(parent, g.cfg.IOTimeout)
	defer cancel()
	e := policy.Event{Protocol: "dns", DNS: meta, ClientIP: ip, Phase: "request"}
	if !g.allowed(e) {
		return dnsReply(req, 5, false)
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", g.upstream)
	if err != nil {
		return dnsReply(req, 2, false)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	query := append([]byte(nil), req...)
	if _, err := rand.Read(query[:2]); err != nil {
		return dnsReply(req, 2, false)
	}
	if err := c.SetDeadline(deadline(ctx, g.cfg.IOTimeout)); err != nil {
		return dnsReply(req, 2, false)
	}
	if _, err := c.Write(query); err != nil {
		return dnsReply(req, 2, false)
	}
	// The extra byte detects datagrams exceeding the configured receive limit.
	buf := make([]byte, g.cfg.MaxDNSResponseBytes+1)
	n, err := c.Read(buf)
	if err != nil {
		return dnsReply(req, 2, false)
	}
	if n > g.cfg.MaxDNSResponseBytes {
		if n < 12 || buf[0] != query[0] || buf[1] != query[1] || word(buf[2:4])&0x8000 == 0 || word(buf[2:4])&0x7840 != 0 {
			return dnsReply(req, 2, false)
		}
		return dnsReply(req, 0, true)
	}
	resp := buf[:n]
	if validateDNSResponse(query, resp, meta) != nil {
		return dnsReply(req, 2, false)
	}
	e.Phase = "response"
	if !g.allowed(e) {
		return dnsReply(req, 5, false)
	}
	if len(resp) > 3*len(req) {
		return dnsReply(req, 0, true)
	}
	copy(resp[:2], req[:2])
	return resp
}

func parseDNSQuery(b []byte) (policy.DNSEvent, error) {
	var m policy.DNSEvent
	if len(b) < 17 || len(b) > maxDNSQuery || word(b[2:4]) & ^(0x0100|0x0010) != 0 || word(b[4:6]) != 1 || word(b[6:8]) != 0 || word(b[8:10]) != 0 || word(b[10:12]) != 0 {
		return m, errDNS
	}
	if validateDNSWire(b) != nil {
		return m, errDNS
	}
	var msg dnsmessage.Message
	if msg.Unpack(b) != nil || len(msg.Questions) != 1 {
		return m, errDNS
	}
	q := msg.Questions[0]
	if q.Class != dnsmessage.ClassINET {
		return m, errDNS
	}
	switch q.Type {
	case 1, 2, 5, 6, 12, 15, 16, 28, 33, 257:
	default:
		return m, errDNS
	}
	m.Name, m.Type = canonicalDNSName(q.Name), int(q.Type)
	return m, nil
}

func validateDNSResponse(req, b []byte, meta policy.DNSEvent) error {
	if len(b) < 12 || b[0] != req[0] || b[1] != req[1] || word(b[2:4])&0x8000 == 0 || word(b[2:4])&0x7840 != 0 || word(b[4:6]) != 1 {
		return errDNS
	}
	if validateDNSWire(b) != nil {
		return errDNS
	}
	var msg dnsmessage.Message
	if msg.Unpack(b) != nil || len(msg.Questions) != 1 {
		return errDNS
	}
	q := msg.Questions[0]
	if canonicalDNSName(q.Name) != meta.Name || int(q.Type) != meta.Type || q.Class != dnsmessage.ClassINET {
		return errDNS
	}
	return nil
}

func canonicalDNSName(name dnsmessage.Name) string {
	// DNS case folding applies only to ASCII, not Unicode or invalid UTF-8 bytes.
	b := []byte(name.String())
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func dnsReply(req []byte, rcode byte, truncated bool) []byte {
	r := append([]byte(nil), req...)
	flags := uint16(0x8000) | binary.BigEndian.Uint16(req[2:4])&0x0110 | uint16(rcode)
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(r[2:4], flags)
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}

// Walk the envelope to reject trailing data and bound record counts before the
// typed DNS parser allocates. Compression pointers must reference prior names.
func validateDNSWire(b []byte) error {
	if len(b) < 12 {
		return errDNS
	}
	questions := word(b[4:6])
	records := word(b[6:8]) + word(b[8:10]) + word(b[10:12])
	if questions != 1 || records > 128 {
		return errDNS
	}
	off := 12
	for i := 0; i < questions+records; i++ {
		end, err := dnsNameEnd(b, off)
		if err != nil {
			return err
		}
		off = end
		if i < questions {
			if off+4 > len(b) {
				return errDNS
			}
			off += 4
		} else {
			if off+10 > len(b) {
				return errDNS
			}
			n := word(b[off+8 : off+10])
			off += 10
			if n > len(b)-off {
				return errDNS
			}
			off += n
		}
	}
	if off != len(b) {
		return errDNS
	}
	return nil
}

func dnsNameEnd(b []byte, off int) (int, error) {
	end, expanded := -1, 0
	for steps := 0; steps < 128; steps++ {
		if off >= len(b) {
			return 0, errDNS
		}
		n := int(b[off])
		if n&0xc0 == 0xc0 {
			if off+1 >= len(b) {
				return 0, errDNS
			}
			ptr := (n&63)<<8 | int(b[off+1])
			if ptr < 12 || ptr >= off {
				return 0, errDNS
			}
			if end == -1 {
				end = off + 2
			}
			off = ptr
			continue
		}
		if n > 63 || off+1+n > len(b) {
			return 0, errDNS
		}
		expanded += n + 1
		if expanded > 255 {
			return 0, errDNS
		}
		off += n + 1
		if n == 0 {
			if end == -1 {
				end = off
			}
			return end, nil
		}
	}
	return 0, errDNS
}
