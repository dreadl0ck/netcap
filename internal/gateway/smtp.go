package gateway

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
)

func (g *Gateway) smtpReply(ctx context.Context, up net.Conn, r *bufio.Reader) ([]byte, int, error) {
	up.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
	var out []byte
	code := 0
	for i := 0; i < 100; i++ {
		b, err := boundedLine(r, 1000)
		if err != nil || len(b) < 6 || !cleanToken(string(b[:len(b)-2])) {
			return nil, 0, errFrame
		}
		n, err := strconv.Atoi(string(b[:3]))
		if err != nil || n < 200 || n > 599 || b[3] != '-' && b[3] != ' ' || code != 0 && code != n {
			return nil, 0, errFrame
		}
		code = n
		out = append(out, b...)
		if len(out) > g.cfg.MaxMessageBytes {
			return nil, 0, errFrame
		}
		if b[3] == ' ' {
			return out, code, nil
		}
	}
	return nil, 0, errFrame
}
func smtpEnvelope(arg, prefix string) (string, bool) {
	if !strings.HasPrefix(strings.ToUpper(arg), prefix) {
		return "", false
	}
	s := arg[len(prefix):]
	if len(s) < 2 || s[0] != '<' {
		return "", false
	}
	end := strings.IndexByte(s, '>')
	if end < 1 {
		return "", false
	}
	addr := s[1:end]
	if strings.ContainsAny(addr, "<>\x00\r\n") {
		return "", false
	}
	if len(s) > end+1 && s[end+1] != ' ' {
		return "", false
	}
	return addr, true
}

func smtpData(r *bufio.Reader, limit int) (wire, body []byte, err error) {
	for {
		l, e := boundedLine(r, 1000)
		if e != nil {
			return nil, nil, e
		}
		if !cleanToken(string(l[:len(l)-2])) || len(wire)+len(l) > limit {
			return nil, nil, errFrame
		}
		wire = append(wire, l...)
		if bytes.Equal(l, []byte(".\r\n")) {
			return wire, body, nil
		}
		if l[0] == '.' {
			if len(l) < 2 || l[1] != '.' {
				return nil, nil, errFrame
			}
			l = l[1:]
		}
		body = append(body, l...)
	}
}
func smtpCapabilities(b []byte) []byte {
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\r\n")), []byte("\r\n"))
	out := [][]byte{}
	for _, l := range lines {
		if len(l) < 4 {
			continue
		}
		v := strings.ToUpper(string(l[4:]))
		key := strings.Fields(v)
		if len(key) > 0 {
			switch key[0] {
			case "STARTTLS", "CHUNKING", "BINARYMIME", "SIZE":
				continue
			}
		}
		out = append(out, append([]byte(nil), l...))
	}
	if len(out) == 0 {
		return []byte("250 gateway\r\n")
	}
	var result []byte
	for i, l := range out {
		l[3] = '-'
		if i == len(out)-1 {
			l[3] = ' '
		}
		result = append(result, l...)
		result = append(result, '\r', '\n')
	}
	return result
}
func (g *Gateway) smtpClient(ctx context.Context, c net.Conn, ip string) {
	up, err := g.dial(ctx)
	if err != nil {
		return
	}
	defer up.Close()
	stop := context.AfterFunc(ctx, func() { up.Close() })
	defer stop()
	ur := bufio.NewReaderSize(up, 4096)
	r := bufio.NewReaderSize(c, 4096)
	reply, code, err := g.smtpReply(ctx, up, ur)
	if err != nil || code != 220 {
		return
	}
	if g.writeFrame(ctx, c, reply) != nil {
		return
	}
	greeted, hasSender := false, false
	sender := ""
	recipients := []string{}
	reset := func() bool {
		hasSender = false
		sender = ""
		recipients = nil
		if g.writeFrame(ctx, up, []byte("RSET\r\n")) != nil {
			return false
		}
		_, n, e := g.smtpReply(ctx, up, ur)
		return e == nil && n == 250
	}
	for i := 0; i < g.cfg.MaxSessionMessages; i++ {
		c.SetReadDeadline(deadline(ctx, g.cfg.IdleTimeout))
		line, err := boundedLine(r, 1000)
		if err != nil {
			return
		}
		text := string(line[:len(line)-2])
		if !cleanToken(text) {
			return
		}
		parts := strings.SplitN(text, " ", 2)
		cmd := redisWord([]byte(parts[0]))
		arg := ""
		if len(parts) == 2 {
			arg = parts[1]
		}
		a := map[string]string{"mail.sender": sender, "mail.command": cmd}
		var address string
		switch cmd {
		case "EHLO", "HELO":
			if arg == "" {
				return
			}
		case "MAIL":
			if !greeted {
				g.writeFrame(ctx, c, []byte("503 send EHLO first\r\n"))
				continue
			}
			var ok bool
			address, ok = smtpEnvelope(arg, "FROM:")
			if !ok {
				return
			}
			a["mail.sender"] = address
		case "RCPT":
			if !hasSender {
				g.writeFrame(ctx, c, []byte("503 send MAIL first\r\n"))
				continue
			}
			var ok bool
			address, ok = smtpEnvelope(arg, "TO:")
			if !ok || address == "" {
				return
			}
			a["mail.recipient"] = address
			if len(recipients) >= g.cfg.MaxStateEntries {
				return
			}
		case "DATA":
			if arg != "" {
				return
			}
			if !hasSender || len(recipients) == 0 {
				g.writeFrame(ctx, c, []byte("503 envelope required\r\n"))
				continue
			}
			if g.writeFrame(ctx, c, []byte("354 end with <CRLF>.<CRLF>\r\n")) != nil {
				return
			}
			c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
			wire, body, err := smtpData(r, g.cfg.MaxMessageBytes)
			if err != nil {
				return
			}
			bodyText := string(body)
			allowed := true
			for _, recipient := range recipients {
				attrs := map[string]string{"mail.command": "DATA", "mail.sender": sender, "mail.recipient": recipient}
				e := event("smtp", "DATA", ip, attrs)
				e.Body = bodyText
				if !g.allowed(e) {
					allowed = false
					break
				}
			}
			if !allowed {
				if !reset() {
					return
				}
				if g.writeFrame(ctx, c, []byte("550 message blocked by gateway\r\n")) != nil {
					return
				}
				continue
			}
			if g.writeFrame(ctx, up, []byte("DATA\r\n")) != nil {
				return
			}
			reply, code, err = g.smtpReply(ctx, up, ur)
			if err != nil {
				return
			}
			if code == 354 {
				if g.writeFrame(ctx, up, wire) != nil {
					return
				}
				reply, code, err = g.smtpReply(ctx, up, ur)
				if err != nil {
					return
				}
			}
			if !reset() {
				return
			}
			if g.writeFrame(ctx, c, reply) != nil {
				return
			}
			continue
		case "STARTTLS":
			g.writeFrame(ctx, c, []byte("502 STARTTLS unsupported; use implicit TLS listener\r\n"))
			continue
		case "BDAT", "BURL":
			g.writeFrame(ctx, c, []byte("502 unsupported transfer mode\r\n"))
			return
		case "RSET", "NOOP", "QUIT":
			if arg != "" && cmd != "NOOP" {
				return
			}
		case "AUTH":
			if !greeted || hasSender {
				return
			}
			a = map[string]string{"mail.command": "AUTH"}
		default:
			g.writeFrame(ctx, c, []byte("502 unsupported command\r\n"))
			continue
		}
		if !g.allowed(event("smtp", cmd, ip, a)) {
			g.writeFrame(ctx, c, []byte("550 command blocked by gateway\r\n"))
			continue
		}
		if g.writeFrame(ctx, up, line) != nil {
			return
		}
		reply, code, err = g.smtpReply(ctx, up, ur)
		if err != nil {
			return
		}
		if cmd == "AUTH" {
			for round := 0; code == 334; round++ {
				if round >= 16 {
					return
				}
				if g.writeFrame(ctx, c, reply) != nil {
					return
				}
				c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
				opaque, e := boundedLine(r, 1000)
				if e != nil || !cleanToken(string(opaque[:len(opaque)-2])) {
					return
				}
				if g.writeFrame(ctx, up, opaque) != nil {
					return
				}
				reply, code, err = g.smtpReply(ctx, up, ur)
				if err != nil {
					return
				}
			}
		}
		if code >= 200 && code < 300 {
			switch cmd {
			case "EHLO", "HELO":
				greeted = true
				hasSender = false
				sender = ""
				recipients = nil
				if cmd == "EHLO" {
					reply = smtpCapabilities(reply)
				}
			case "MAIL":
				hasSender = true
				sender = address
				recipients = nil
			case "RCPT":
				recipients = append(recipients, address)
			case "RSET":
				hasSender = false
				sender = ""
				recipients = nil
			}
		}
		if g.writeFrame(ctx, c, reply) != nil {
			return
		}
		if cmd == "QUIT" {
			return
		}
	}
}
