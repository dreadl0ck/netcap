package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
)

func pgFrame(kind byte, b []byte) []byte {
	out := make([]byte, 5, len(b)+5)
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:], uint32(len(b)+4))
	return append(out, b...)
}
func (g *Gateway) pgRead(ctx context.Context, c net.Conn, startup bool) ([]byte, error) {
	n := 5
	if startup {
		n = 4
	}
	h := make([]byte, n)
	c.SetReadDeadline(deadline(ctx, g.cfg.IdleTimeout))
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return nil, err
	}
	c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
	if _, err := io.ReadFull(c, h[1:]); err != nil {
		return nil, err
	}
	off := 1
	if startup {
		off = 0
	}
	size := int(binary.BigEndian.Uint32(h[off:]))
	if size < 4 || size > g.cfg.MaxMessageBytes {
		return nil, errFrame
	}
	b := make([]byte, size-4)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return append(h, b...), nil
}
func pgCString(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}
func pgStartup(b []byte) (map[string]string, bool) {
	if len(b) < 9 || binary.BigEndian.Uint32(b[4:8]) != 196608 {
		return nil, false
	}
	a := map[string]string{}
	rest := b[8:]
	seen := map[string]bool{}
	for len(rest) > 1 {
		if len(seen) >= 128 {
			return nil, false
		}
		k, r, ok := pgCString(rest)
		if !ok || k == "" || seen[k] {
			return nil, false
		}
		seen[k] = true
		v, r, ok := pgCString(r)
		if !ok {
			return nil, false
		}
		rest = r
		switch k {
		case "user":
			a["db.username"] = v
		case "database":
			a["db.database"] = v
		}
	}
	if len(rest) != 1 || rest[0] != 0 || a["db.username"] == "" {
		return nil, false
	}
	if a["db.database"] == "" {
		a["db.database"] = a["db.username"]
	}
	return a, true
}
func pgDenied() []byte {
	return pgFrame('E', []byte("SFATAL\x00C42501\x00Mblocked or unsupported by gateway\x00\x00"))
}

// pgRelay stops at an authentication challenge or a command boundary. Flush
// after extended messages makes ordinary pipelined drivers progress without
// waiting for a Sync that is still buffered behind the current message.
func (g *Gateway) pgRelay(ctx context.Context, c, up net.Conn, terminal string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.IOTimeout)
	defer cancel()
	total := 0
	for i := 0; i < g.cfg.MaxSessionMessages; i++ {
		b, err := g.pgRead(ctx, up, false)
		if err != nil {
			return false, err
		}
		total += len(b)
		if total > g.cfg.MaxMessageBytes {
			return false, errFrame
		}
		if b[0] == 'G' || b[0] == 'H' || b[0] == 'W' {
			return false, errFrame
		} // COPY is not an opaque bypass.
		if g.writeFrame(ctx, c, b) != nil {
			return false, errFrame
		}
		if b[0] == 'E' {
			return false, errFrame
		} // Close instead of fabricating Sync recovery.
		if terminal == "auth" && b[0] == 'R' {
			if len(b) < 9 {
				return false, errFrame
			}
			code := binary.BigEndian.Uint32(b[5:9])
			switch code {
			case 0, 12:
			case 3, 5, 10, 11:
				return true, nil
			default:
				return false, errFrame
			}
		}
		if terminal == "auth" && b[0] == 'Z' {
			return false, nil
		}
		if terminal != "auth" && bytes.IndexByte([]byte(terminal), b[0]) >= 0 {
			return b[0] == 'Z' && len(b) == 6 && b[5] == 'I', nil
		}
	}
	return false, errFrame
}

type pgState struct{ statements, portals map[string]string }

func (s *pgState) size() int {
	n := 0
	for k, v := range s.statements {
		n += len(k) + len(v)
	}
	for k, v := range s.portals {
		n += len(k) + len(v)
	}
	return n
}

func pgParse(b []byte) (name, query string, ok bool) {
	name, r, ok := pgCString(b)
	if !ok {
		return "", "", false
	}
	query, r, ok = pgCString(r)
	if !ok || len(r) < 2 || len(r) != 2+4*word(r[:2]) {
		return "", "", false
	}
	return name, query, true
}
func pgBind(b []byte) (portal, statement string, ok bool) {
	portal, r, ok := pgCString(b)
	if !ok {
		return "", "", false
	}
	statement, r, ok = pgCString(r)
	if !ok || len(r) < 2 {
		return "", "", false
	}
	formats := word(r[:2])
	r = r[2:]
	if len(r) < 2*formats+2 {
		return "", "", false
	}
	for i := 0; i < formats; i++ {
		if word(r[2*i:2*i+2]) > 1 {
			return "", "", false
		}
	}
	r = r[2*formats:]
	count := word(r[:2])
	r = r[2:]
	if formats != 0 && formats != 1 && formats != count {
		return "", "", false
	}
	for i := 0; i < count; i++ {
		if len(r) < 4 {
			return "", "", false
		}
		n := int(int32(binary.BigEndian.Uint32(r[:4])))
		r = r[4:]
		if n < -1 || n > len(r) {
			return "", "", false
		}
		if n >= 0 {
			r = r[n:]
		}
	}
	if len(r) < 2 {
		return "", "", false
	}
	n := word(r[:2])
	r = r[2:]
	if len(r) != 2*n {
		return "", "", false
	}
	for i := 0; i < n; i++ {
		if word(r[2*i:2*i+2]) > 1 {
			return "", "", false
		}
	}
	return portal, statement, true
}

func (g *Gateway) postgresClient(ctx context.Context, c net.Conn, ip string) {
	b, err := g.pgRead(ctx, c, true)
	if err != nil {
		return
	}
	if len(b) == 8 && binary.BigEndian.Uint32(b[4:]) == 80877103 {
		if g.cfg.TLSCert == "" {
			if g.writeFrame(ctx, c, []byte("N")) != nil {
				return
			}
		} else {
			if g.writeFrame(ctx, c, []byte("S")) != nil {
				return
			}
			tc := tls.Server(c, g.serverTLS)
			tc.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
			if tc.HandshakeContext(ctx) != nil {
				return
			}
			c = tc
		}
		b, err = g.pgRead(ctx, c, true)
		if err != nil {
			return
		}
	} else if g.cfg.TLSCert != "" {
		g.writeFrame(ctx, c, pgDenied())
		return
	}
	attrs, ok := pgStartup(b)
	if !ok {
		return
	}
	attrs["db.command"] = "STARTUP"
	if !g.allowed(event("postgres", "STARTUP", ip, attrs)) {
		g.writeFrame(ctx, c, pgDenied())
		return
	}
	up, err := g.dial(ctx)
	if err != nil {
		return
	}
	defer up.Close()
	stop := context.AfterFunc(ctx, func() { up.Close() })
	defer stop()
	if g.writeFrame(ctx, up, b) != nil {
		return
	}
	for challenges := 0; ; challenges++ {
		need, err := g.pgRelay(ctx, c, up, "auth")
		if err != nil {
			return
		}
		if !need {
			break
		}
		if challenges >= 16 {
			return
		}
		b, err = g.pgRead(ctx, c, false)
		if err != nil || b[0] != 'p' {
			return
		}
		// Password, MD5 and SCRAM payloads are forwarded only as bounded opaque bytes.
		if g.writeFrame(ctx, up, b) != nil {
			return
		}
	}
	state := pgState{map[string]string{}, map[string]string{}}
	for i := 0; i < g.cfg.MaxSessionMessages; i++ {
		b, err = g.pgRead(ctx, c, false)
		if err != nil {
			return
		}
		p := b[5:]
		cmd, query, name, terminal := "", "", "", ""
		var change func()
		switch b[0] {
		case 'Q':
			var rest []byte
			query, rest, ok = pgCString(p)
			if !ok || len(rest) != 0 {
				return
			}
			cmd, terminal = "QUERY", "Z"
			change = func() { delete(state.statements, ""); delete(state.portals, "") }
		case 'P':
			name, query, ok = pgParse(p)
			if !ok {
				return
			}
			cmd, terminal = "PARSE", "1"
			change = func() { state.statements[name] = query }
		case 'B':
			var stmt string
			name, stmt, ok = pgBind(p)
			if !ok {
				return
			}
			query, ok = state.statements[stmt]
			if !ok {
				return
			}
			cmd, terminal = "BIND", "2"
			change = func() { state.portals[name] = query }
		case 'E':
			var rest []byte
			name, rest, ok = pgCString(p)
			if !ok || len(rest) != 4 {
				return
			}
			query, ok = state.portals[name]
			if !ok {
				return
			}
			cmd, terminal = "EXECUTE", "CsI"
		case 'D', 'C':
			if len(p) < 2 || p[0] != 'S' && p[0] != 'P' {
				return
			}
			var rest []byte
			name, rest, ok = pgCString(p[1:])
			if !ok || len(rest) != 0 {
				return
			}
			table := state.statements
			if p[0] == 'P' {
				table = state.portals
			}
			query, ok = table[name]
			if !ok {
				return
			}
			if b[0] == 'C' {
				cmd, terminal = "CLOSE", "3"
				change = func() { delete(table, name) }
			} else {
				cmd = "DESCRIBE"
				if p[0] == 'S' {
					terminal = "Tn"
				} else {
					terminal = "Tn"
				}
			}
		case 'S':
			if len(p) != 0 {
				return
			}
			cmd, terminal = "SYNC", "Z"
		case 'H':
			if len(p) != 0 {
				return
			}
			continue
		case 'X':
			if len(p) != 0 {
				return
			}
			g.writeFrame(ctx, up, b)
			return
		default:
			g.writeFrame(ctx, c, pgDenied())
			return
		}
		a := map[string]string{"db.command": cmd, "db.username": attrs["db.username"], "db.database": attrs["db.database"]}
		if query != "" {
			a["db.query"] = query
		}
		if !g.allowed(event("postgres", cmd, ip, a)) {
			g.writeFrame(ctx, c, pgDenied())
			return
		}
		if (b[0] == 'P' || b[0] == 'B') && (len(state.statements)+len(state.portals) >= g.cfg.MaxStateEntries || state.size()+len(name)+len(query) > g.cfg.MaxMessageBytes) {
			g.writeFrame(ctx, c, pgDenied())
			return
		}
		if g.writeFrame(ctx, up, b) != nil {
			return
		}
		if b[0] != 'Q' && b[0] != 'S' {
			if g.writeFrame(ctx, up, pgFrame('H', nil)) != nil {
				return
			}
		}
		idle, relayErr := g.pgRelay(ctx, c, up, terminal)
		if relayErr != nil {
			return
		}
		if change != nil {
			change()
		}
		if idle {
			state.portals = map[string]string{}
		}
	}
}
