//go:build coraza && http3

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/internal/gateway"
	"github.com/dreadl0ck/netcap/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

// Scripted, owned protocol peers, not vendor server/version compatibility claims.
type wireFixture struct {
	ledger  *ledger
	address string
	close   func()
}

func (l *ledger) recordWire(b []byte, bad bool) {
	l.Requests.Add(1)
	l.Bytes.Add(uint64(len(b)))
	if bad {
		l.ForbiddenRequests.Add(1)
		l.ForbiddenBytes.Add(uint64(len(b)))
		l.ForbiddenEffects.Add(1)
	}
}

func tcpFixture(handler func(net.Conn, *ledger)) (*wireFixture, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &wireFixture{ledger: &ledger{}, address: l.Addr().String()}
	var wg sync.WaitGroup
	var mu sync.Mutex
	clients := map[net.Conn]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			clients[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close(); mu.Lock(); delete(clients, c); mu.Unlock() }()
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				handler(c, f.ledger)
			}()
		}
	}()
	f.close = func() {
		_ = l.Close()
		<-done
		mu.Lock()
		for c := range clients {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
	return f, nil
}

func boundedFrame(c net.Conn, header, offset, width int, little bool, subtract int) ([]byte, error) {
	b := make([]byte, header)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	n := 0
	for i := 0; i < width; i++ {
		j := i
		if !little {
			j = width - 1 - i
		}
		n |= int(b[offset+i]) << (8 * j)
	}
	n -= subtract
	if n < 0 || n > 65536 {
		return nil, errors.New("fixture frame bound")
	}
	p := make([]byte, n)
	_, err := io.ReadFull(c, p)
	return append(b, p...), err
}

func pgPacket(kind byte, body []byte) []byte {
	b := make([]byte, 5)
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], uint32(len(body)+4))
	return append(b, body...)
}

func mysqlPacket(seq byte, body []byte) []byte {
	n := len(body)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, body...)
}

const mysqlFlags uint32 = 1<<9 | 1<<15 | 1<<19

func mysqlGreeting() []byte {
	b := append([]byte{10}, []byte("8.4.8-scripted-qualification\x00")...)
	b = append(b, 1, 0, 0, 0)
	b = append(b, []byte("12345678")...)
	b = append(b, 0, byte(mysqlFlags&255), byte(mysqlFlags>>8&255), 45, 2, 0, byte(mysqlFlags>>16&255), byte(mysqlFlags>>24), 21)
	b = append(b, make([]byte, 10)...)
	return append(b, []byte("abcdefghijkl\x00caching_sha2_password\x00")...)
}

func respPacket(args ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.Bytes()
}

func readRESPFixture(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var count int
	if _, err := fmt.Sscanf(line, "*%d", &count); err != nil || count < 1 || count > 16 {
		return nil, errors.New("fixture RESP array")
	}
	out := []byte(line)
	for i := 0; i < count; i++ {
		line, err = r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		var n int
		if _, err := fmt.Sscanf(line, "$%d", &n); err != nil || n < 0 || n > 4096 {
			return nil, errors.New("fixture RESP bulk")
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		out = append(append(out, []byte(line)...), b...)
	}
	return out, nil
}

func modbusPacket(write bool) []byte {
	pdu := []byte{3, 0, 100, 0, 1}
	if write {
		pdu = []byte{6, 0, 100, 0, 99}
	}
	b := []byte{0, 1, 0, 0, 0, byte(len(pdu) + 1), 1}
	return append(b, pdu...)
}

func dnpCRC(b []byte) uint16 {
	var crc uint16
	for _, v := range b {
		crc ^= uint16(v)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}

func dnpPacket(response, attack bool) []byte {
	data := []byte{0xc1, 0xc1, 1, 60, 2, 6}
	control, dest, source := byte(0xc4), byte(3), byte(4)
	if attack {
		data = append([]byte{0xc1, 0xc1, 4}, []byte{12, 1, 0x17, 1, 99, 3, 1, 100, 0, 0, 0, 100, 0, 0, 0, 0}...)
	}
	if response {
		control, dest, source = 0x44, 4, 3
		data = []byte{0xc0, 0xc1, 129, 0, 0, 1, 2, 0, 0, 0, 1}
	}
	b := []byte{5, 0x64, byte(len(data) + 5), control, dest, 0, source, 0}
	crc := dnpCRC(b)
	b = append(b, byte(crc), byte(crc>>8))
	for len(data) > 0 {
		n := min(16, len(data))
		chunk := data[:n]
		crc = dnpCRC(chunk)
		b = append(b, chunk...)
		b = append(b, byte(crc), byte(crc>>8))
		data = data[n:]
	}
	return b
}

func readDNPFixture(c net.Conn) ([]byte, error) {
	b := make([]byte, 10)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	n := int(b[2]) - 5
	if n < 0 || n > 250 {
		return nil, errors.New("fixture DNP length")
	}
	p := make([]byte, n+2*((n+15)/16))
	_, err := io.ReadFull(c, p)
	return append(b, p...), err
}

func newTCPProfile(ctx context.Context, protocol string) (*profile, error) {
	expression := map[string]string{
		"redis":    `Method == "FLUSHALL"`,
		"postgres": `Attributes["db.query"] contains "qualification-forbidden-marker"`,
		"mysql":    `Attributes["db.query"] contains "qualification-forbidden-marker"`,
		"smtp":     `Body contains "qualification-forbidden-marker"`,
		"modbus":   `Modbus.IsWrite && Modbus.EndAddress >= 100`,
		"dnp3":     `Attributes["dnp3.object_group"] == "12" && Attributes["dnp3.address_end"] == "99"`,
	}[protocol]
	p := &profile{Name: protocol + "-scripted-v1", Ledger: &ledger{}, Fixture: protocol + " owned scripted peer; no vendor compatibility claim"}
	f, err := tcpFixture(func(c net.Conn, l *ledger) {
		switch protocol {
		case "redis":
			r := bufio.NewReader(c)
			for {
				b, err := readRESPFixture(r)
				if err != nil {
					return
				}
				l.recordWire(b, bytes.Contains(b, []byte("FLUSHALL")))
				if _, err = c.Write([]byte("+OK\r\n")); err != nil {
					return
				}
			}
		case "postgres":
			b, err := boundedFrame(c, 4, 0, 4, false, 4)
			if err != nil {
				return
			}
			l.recordWire(b, false)
			_, _ = c.Write(append(pgPacket('R', []byte{0, 0, 0, 0}), pgPacket('Z', []byte{'I'})...))
			for {
				b, err = boundedFrame(c, 5, 1, 4, false, 4)
				if err != nil {
					return
				}
				l.recordWire(b, bytes.Contains(b, []byte(forbidden)))
				if b[0] == 'X' {
					return
				}
				_, _ = c.Write(append(pgPacket('C', []byte("SELECT 1\x00")), pgPacket('Z', []byte{'I'})...))
			}
		case "mysql":
			_, _ = c.Write(mysqlPacket(0, mysqlGreeting()))
			b, err := boundedFrame(c, 4, 0, 3, true, 0)
			if err != nil {
				return
			}
			l.recordWire(b, false)
			_, _ = c.Write(mysqlPacket(2, []byte{0, 0, 0, 2, 0, 0, 0}))
			for {
				b, err = boundedFrame(c, 4, 0, 3, true, 0)
				if err != nil {
					return
				}
				l.recordWire(b, bytes.Contains(b, []byte(forbidden)))
				_, _ = c.Write(mysqlPacket(1, []byte{0, 0, 0, 2, 0, 0, 0}))
			}
		case "smtp":
			_, _ = io.WriteString(c, "220 owned fixture\r\n")
			r := bufio.NewReader(c)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				l.recordWire([]byte(line), strings.Contains(line, forbidden))
				if strings.HasPrefix(line, "DATA") {
					_, _ = io.WriteString(c, "354 data\r\n")
					for {
						line, err = r.ReadString('\n')
						if err != nil {
							return
						}
						l.recordWire([]byte(line), strings.Contains(line, forbidden))
						if line == ".\r\n" {
							break
						}
					}
				}
				_, _ = io.WriteString(c, "250 ok\r\n")
			}
		case "modbus":
			for {
				b, err := boundedFrame(c, 7, 4, 2, false, 1)
				if err != nil {
					return
				}
				l.recordWire(b, len(b) > 7 && b[7] == 6)
				_, _ = c.Write([]byte{b[0], b[1], 0, 0, 0, 5, 1, 3, 2, 0, 42})
			}
		case "dnp3":
			for {
				b, err := readDNPFixture(c)
				if err != nil {
					return
				}
				l.recordWire(b, len(b) > 12 && b[12] == 4)
				_, _ = c.Write(dnpPacket(true, false))
			}
		}
	})
	if err != nil {
		return nil, err
	}
	p.Ledger = f.ledger
	compiled, err := policy.Compile(policy.Bundle{Version: "v1", ID: "qualification-" + protocol, Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "protect", Action: "deny", Expression: expression}}})
	if err != nil {
		f.close()
		return nil, err
	}
	g, err := gateway.New(gateway.Config{Protocol: protocol, Upstream: f.address, MaxConnections: 32, MaxMessageBytes: 65536, MaxStateEntries: 128, IOTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second}, compiled)
	if err != nil {
		f.close()
		return nil, err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.close()
		return nil, err
	}
	local, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- g.Serve(local, l) }()
	p.Close = func() { cancel(); _ = l.Close(); <-done; f.close() }
	p.CustomRequest = func(w workflow) (int, int, error) {
		attack := strings.Contains(w.Body, forbidden)
		c, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
		if err != nil {
			return 0, 0, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		status, err := exchangeWire(c, protocol, attack)
		return status, 0, err
	}
	return p, nil
}

func expectLine(r *bufio.Reader, prefix string) error {
	for {
		b, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(b, prefix) {
			return fmt.Errorf("fixture reply: want %s got %q", prefix, b)
		}
		if len(b) < 4 || b[3] != '-' {
			return nil
		}
	}
}

func exchangeWire(c net.Conn, protocol string, attack bool) (int, error) {
	status := 200
	if attack {
		status = 403
	}
	switch protocol {
	case "redis":
		b := respPacket("SET", "synthetic", "safe")
		if attack {
			b = respPacket("FLUSHALL")
		}
		if _, err := c.Write(b); err != nil {
			return 0, err
		}
		prefix := "+OK"
		if attack {
			prefix = "-NOPERM"
		}
		return status, expectLine(bufio.NewReader(c), prefix)
	case "postgres":
		b := append([]byte{0, 0, 0, 0, 0, 3, 0, 0}, []byte("user\x00synthetic\x00database\x00fixture\x00\x00")...)
		binary.BigEndian.PutUint32(b, uint32(len(b)))
		if _, err := c.Write(b); err != nil {
			return 0, err
		}
		for _, kind := range []byte{'R', 'Z'} {
			b, err := boundedFrame(c, 5, 1, 4, false, 4)
			if err != nil {
				return 0, err
			}
			if b[0] != kind {
				return 0, errors.New("PG startup reply")
			}
		}
		query := "SELECT 1"
		if attack {
			query = "DELETE FROM " + forbidden
		}
		_, err := c.Write(pgPacket('Q', append([]byte(query), 0)))
		if err != nil {
			return 0, err
		}
		b, err = boundedFrame(c, 5, 1, 4, false, 4)
		if err != nil {
			return 0, err
		}
		want := byte('C')
		if attack {
			want = 'E'
		}
		if b[0] != want {
			return 0, errors.New("PG query result")
		}
		return status, nil
	case "mysql":
		if _, err := boundedFrame(c, 4, 0, 3, true, 0); err != nil {
			return 0, err
		}
		b := make([]byte, 32)
		binary.LittleEndian.PutUint32(b, mysqlFlags)
		binary.LittleEndian.PutUint32(b[4:], 65536)
		b[8] = 45
		b = append(b, []byte("synthetic\x00\x00caching_sha2_password\x00")...)
		if _, err := c.Write(mysqlPacket(1, b)); err != nil {
			return 0, err
		}
		if _, err := boundedFrame(c, 4, 0, 3, true, 0); err != nil {
			return 0, err
		}
		query := "SELECT 1"
		if attack {
			query = "DELETE FROM " + forbidden
		}
		if _, err := c.Write(mysqlPacket(0, append([]byte{3}, []byte(query)...))); err != nil {
			return 0, err
		}
		b, err := boundedFrame(c, 4, 0, 3, true, 0)
		if err != nil {
			return 0, err
		}
		want := byte(0)
		if attack {
			want = 255
		}
		if len(b) < 5 || b[4] != want {
			return 0, errors.New("MySQL query result")
		}
		return status, nil
	case "smtp":
		r := bufio.NewReader(c)
		if err := expectLine(r, "220"); err != nil {
			return 0, err
		}
		for _, cmd := range []string{"EHLO synthetic\r\n", "MAIL FROM:<synthetic@fixture.test>\r\n", "RCPT TO:<sink@fixture.test>\r\n"} {
			if _, err := io.WriteString(c, cmd); err != nil {
				return 0, err
			}
			if err := expectLine(r, "250"); err != nil {
				return 0, err
			}
		}
		if _, err := io.WriteString(c, "DATA\r\n"); err != nil {
			return 0, err
		}
		if err := expectLine(r, "354"); err != nil {
			return 0, err
		}
		body := "synthetic invoice"
		if attack {
			body = forbidden
		}
		if _, err := io.WriteString(c, "Subject: owned fixture\r\n\r\n"+body+"\r\n.\r\n"); err != nil {
			return 0, err
		}
		prefix := "250"
		if attack {
			prefix = "550"
		}
		return status, expectLine(r, prefix)
	case "modbus":
		if _, err := c.Write(modbusPacket(attack)); err != nil {
			return 0, err
		}
		b, err := boundedFrame(c, 7, 4, 2, false, 1)
		if err != nil {
			return 0, err
		}
		want := byte(3)
		if attack {
			want = 0x86
		}
		if len(b) < 9 || b[7] != want {
			return 0, errors.New("Modbus result")
		}
		return status, nil
	case "dnp3":
		if _, err := c.Write(dnpPacket(false, attack)); err != nil {
			return 0, err
		}
		b, err := readDNPFixture(c)
		if attack {
			if errors.Is(err, io.EOF) {
				return status, nil
			}
			return 0, fmt.Errorf("DNP3 denied stream should close: %x %v", b, err)
		}
		if err != nil {
			return 0, err
		}
		if !bytes.Equal(b, dnpPacket(true, false)) {
			return 0, errors.New("DNP3 response mismatch")
		}
		return status, nil
	}
	return 0, errors.New("unwired protocol")
}

func newDNSProfile(ctx context.Context) (*profile, error) {
	origin, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &profile{Name: "dns-udp-scripted-v1", Ledger: &ledger{}, Fixture: "DNS RFC1035 A question/compressed A answer; owned scripted peer"}
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		b := make([]byte, 4096)
		for {
			n, a, err := origin.ReadFrom(b)
			if err != nil {
				return
			}
			p.Ledger.recordWire(b[:n], bytes.Contains(b[:n], []byte(forbidden)))
			r := append([]byte(nil), b[:n]...)
			r[2], r[3], r[6], r[7] = 0x81, 0x80, 0, 1
			r = append(r, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1)
			_, _ = origin.WriteTo(r, a)
		}
	}()
	compiled, err := policy.Compile(policy.Bundle{Version: "v1", ID: "qualification-dns", Mode: "enforce", Default: "allow", Rules: []policy.Rule{{ID: "protect", Action: "deny", Expression: `DNS.Name contains "qualification-forbidden-marker"`}}})
	if err != nil {
		_ = origin.Close()
		<-originDone
		return nil, err
	}
	g, err := gateway.New(gateway.Config{Protocol: "dns", Upstream: origin.LocalAddr().String()}, compiled)
	if err != nil {
		_ = origin.Close()
		<-originDone
		return nil, err
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = origin.Close()
		<-originDone
		return nil, err
	}
	local, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- g.ServePacket(local, pc) }()
	p.Close = func() { cancel(); _ = pc.Close(); <-done; _ = origin.Close(); <-originDone }
	p.CustomRequest = func(w workflow) (int, int, error) {
		attack := strings.Contains(w.Body, forbidden)
		name := "safe.fixture.test."
		if attack {
			name = forbidden + ".test."
		}
		n, err := dnsmessage.NewName(name)
		if err != nil {
			return 0, 0, err
		}
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		b, err := m.Pack()
		if err != nil {
			return 0, 0, err
		}
		c, err := net.DialTimeout("udp", pc.LocalAddr().String(), time.Second)
		if err != nil {
			return 0, 0, err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = c.Write(b); err != nil {
			return 0, 0, err
		}
		b = make([]byte, 4096)
		size, err := c.Read(b)
		if err != nil {
			return 0, 0, err
		}
		if err = m.Unpack(b[:size]); err != nil {
			return 0, 0, err
		}
		want := dnsmessage.RCodeSuccess
		status := 200
		if attack {
			want = dnsmessage.RCodeRefused
			status = 403
		}
		if m.RCode != want || (!attack && len(m.Answers) != 1) {
			return 0, 0, errors.New("DNS response mismatch")
		}
		return status, 0, nil
	}
	return p, nil
}
