package gateway

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

func ftpControlText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, b := range []byte(s) {
		if b < 32 || b == 127 {
			return false
		}
	}
	return true
}

// RFC 959 multiline replies may have arbitrary intermediate lines. Both the
// line count and total bytes are bounded before any reply is released.
func (g *Gateway) ftpReply(ctx context.Context, c net.Conn, r *bufio.Reader) ([]byte, int, error) {
	c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
	var out []byte
	code := 0
	for n := 0; n < 100; n++ {
		b, err := boundedLine(r, min(4096, g.cfg.MaxMessageBytes))
		if err != nil || !cleanToken(string(b[:len(b)-2])) {
			return nil, 0, errFrame
		}
		if n == 0 {
			if len(b) < 6 || b[3] != ' ' && b[3] != '-' {
				return nil, 0, errFrame
			}
			code, err = strconv.Atoi(string(b[:3]))
			if err != nil || code < 100 || code > 599 {
				return nil, 0, errFrame
			}
		}
		if len(out)+len(b) > g.cfg.MaxMessageBytes {
			return nil, 0, errFrame
		}
		out = append(out, b...)
		if len(b) >= 4 && string(b[:4]) == fmt.Sprintf("%03d ", code) {
			return out, code, nil
		}
	}
	return nil, 0, errFrame
}

func ftpPassivePort(reply []byte) (int, error) {
	s := string(reply)
	i := strings.Index(s, "(")
	j := strings.Index(s, ")")
	if i < 0 || j <= i {
		return 0, errFrame
	}
	v := s[i+1 : j]
	if len(v) < 5 || v[0] != '|' || !strings.HasPrefix(v, "|||") || v[len(v)-1] != '|' {
		return 0, errFrame
	}
	n, err := strconv.Atoi(v[3 : len(v)-1])
	if err != nil || n < 1024 || n > 65535 {
		return 0, errFrame
	}
	return n, nil
}

func (g *Gateway) ftpClient(ctx context.Context, c net.Conn, ip string) {
	up, err := g.dial(ctx)
	if err != nil {
		return
	}
	defer up.Close()
	stop := context.AfterFunc(ctx, func() { up.Close() })
	defer stop()
	r, ur := bufio.NewReaderSize(c, 4096), bufio.NewReaderSize(up, 4096)
	reply, code, err := g.ftpReply(ctx, up, ur)
	if err != nil || code != 220 || g.writeFrame(ctx, c, reply) != nil {
		return
	}
	var passive *net.TCPListener
	var target string
	clear := func() {
		if passive != nil {
			passive.Close()
			passive = nil
		}
		target = ""
	}
	defer clear()
	for n := 0; n < g.cfg.MaxSessionMessages; n++ {
		c.SetReadDeadline(deadline(ctx, g.cfg.IdleTimeout))
		line, err := boundedLine(r, min(4096, g.cfg.MaxMessageBytes))
		if err != nil {
			return
		}
		text := string(line[:len(line)-2])
		if !ftpControlText(text) {
			return
		}
		parts := strings.SplitN(text, " ", 2)
		cmd := redisWord([]byte(parts[0]))
		arg := ""
		if len(parts) == 2 {
			arg = parts[1]
		}
		a := map[string]string{"ftp.command": cmd, "ftp.coverage": "command"}
		switch cmd {
		case "USER", "PASS", "ACCT": // Credentials are relayed but never projected into events.
		case "CWD", "CDUP", "PWD", "TYPE", "SYST", "NOOP", "QUIT", "DELE", "MKD", "RMD", "SIZE", "MDTM", "RNFR", "RNTO":
			a["ftp.argument"] = arg
		case "EPSV":
			if arg != "" {
				return
			}
		case "STOR", "RETR", "LIST", "NLST":
			a["ftp.path"] = arg
		default:
			// Active destinations, TLS upgrades, compressed/extended transfers and
			// unknown commands cannot escape onto an unowned data connection.
			clear()
			if g.writeFrame(ctx, c, []byte("502 unsupported command; EPSV stream mode only\r\n")) != nil {
				return
			}
			continue
		}
		if !g.allowed(event("ftp", cmd, ip, a)) {
			clear()
			if g.writeFrame(ctx, c, []byte("550 blocked by gateway\r\n")) != nil {
				return
			}
			continue
		}
		if cmd == "EPSV" {
			clear()
			if g.writeFrame(ctx, up, line) != nil {
				return
			}
			reply, code, err = g.ftpReply(ctx, up, ur)
			if err != nil {
				return
			}
			if code != 229 {
				if g.writeFrame(ctx, c, reply) != nil {
					return
				}
				continue
			}
			port, err := ftpPassivePort(reply)
			if err != nil {
				return
			}
			// Never use an address supplied in an FTP response. Pin the same control peer.
			host, _, _ := net.SplitHostPort(up.RemoteAddr().String())
			target = net.JoinHostPort(host, strconv.Itoa(port))
			local := c.LocalAddr().(*net.TCPAddr)
			passive, err = net.ListenTCP("tcp", &net.TCPAddr{IP: local.IP, Zone: local.Zone})
			if err != nil {
				return
			}
			if g.writeFrame(ctx, c, []byte(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)\r\n", passive.Addr().(*net.TCPAddr).Port))) != nil {
				return
			}
			continue
		}
		if cmd == "STOR" || cmd == "RETR" || cmd == "LIST" || cmd == "NLST" {
			if passive == nil {
				if g.writeFrame(ctx, c, []byte("425 use EPSV first\r\n")) != nil {
					return
				}
				continue
			}
			if !g.ftpTransfer(ctx, c, up, ur, passive, target, ip, cmd, line, a) {
				return
			}
			clear()
			continue
		}
		if g.writeFrame(ctx, up, line) != nil {
			return
		}
		reply, code, err = g.ftpReply(ctx, up, ur)
		if err != nil || code < 200 || code == 334 {
			return
		}
		if g.writeFrame(ctx, c, reply) != nil || cmd == "QUIT" {
			return
		}
	}
}

func (g *Gateway) ftpTransfer(ctx context.Context, c, up net.Conn, ur *bufio.Reader, l *net.TCPListener, target, ip, cmd string, line []byte, attrs map[string]string) bool {
	// The synthetic preliminary reply lets an upload finish before STOR can have
	// a native file-system effect. No origin data socket exists until authorization.
	if g.writeFrame(ctx, c, []byte("150 gateway buffering bounded transfer\r\n")) != nil {
		return false
	}
	l.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	down, err := l.AcceptTCP()
	if err != nil {
		return false
	}
	defer down.Close()
	host, _, _ := net.SplitHostPort(down.RemoteAddr().String())
	if host != ip {
		return false
	}
	stopDown := context.AfterFunc(ctx, func() { down.Close() })
	defer stopDown()
	down.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
	var body []byte
	if cmd == "STOR" {
		body, err = io.ReadAll(io.LimitReader(down, int64(g.cfg.MaxMessageBytes)+1))
		if err != nil || len(body) > g.cfg.MaxMessageBytes {
			return false
		}
		a := make(map[string]string, len(attrs)+1)
		for k, v := range attrs {
			a[k] = v
		}
		a["ftp.coverage"] = "content"
		e := event("ftp", cmd, ip, a)
		e.Body = string(body)
		if !g.allowed(e) {
			return g.writeFrame(ctx, c, []byte("550 transfer blocked by gateway\r\n")) == nil
		}
	}
	data, err := (&net.Dialer{Timeout: g.cfg.IOTimeout}).DialContext(ctx, "tcp", target)
	if err != nil {
		return false
	}
	defer data.Close()
	stopData := context.AfterFunc(ctx, func() { data.Close() })
	defer stopData()
	data.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
	if g.writeFrame(ctx, up, line) != nil {
		return false
	}
	reply, code, err := g.ftpReply(ctx, up, ur)
	if err != nil {
		return false
	}
	if code != 125 && code != 150 {
		return code >= 200 && g.writeFrame(ctx, c, reply) == nil
	}
	if cmd == "STOR" {
		if g.writeFrame(ctx, data, body) != nil {
			return false
		}
		data.Close()
	} else {
		body, err = io.ReadAll(io.LimitReader(data, int64(g.cfg.MaxMessageBytes)+1))
		if err != nil || len(body) > g.cfg.MaxMessageBytes {
			return false
		}
		data.Close()
		e := event("ftp", cmd, ip, attrs)
		e.Phase = "response"
		e.Body = string(body)
		if !g.allowed(e) {
			return false
		}
		if _, err = io.Copy(down, bytes.NewReader(body)); err != nil {
			return false
		}
	}
	down.Close()
	reply, code, err = g.ftpReply(ctx, up, ur)
	return err == nil && code >= 200 && g.writeFrame(ctx, c, reply) == nil
}
