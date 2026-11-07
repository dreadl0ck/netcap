package gateway

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strconv"
)

type mysqlStatement struct {
	query         string
	parameters    int
	database      string
	databaseKnown bool
}

// Authentication sequence numbers are independent on the two TLS-terminated
// legs. Command exchanges restart at zero after authentication completes.
func (g *Gateway) mysqlAuth(ctx context.Context, c, up net.Conn, ip string) (net.Conn, net.Conn, map[string]string, uint32, error) {
	greeting, err := g.mysqlRead(ctx, up, 0, false)
	if err != nil {
		return c, up, nil, 0, err
	}
	lo, hi, charset, serverCaps, ok := mysqlGreeting(greeting)
	if !ok {
		return c, up, nil, 0, errFrame
	}
	offered := serverCaps & mysqlCapabilities
	upSeq := byte(1)
	if g.cfg.UpstreamTLS {
		if serverCaps&mysqlSSL == 0 {
			return c, up, nil, 0, errFrame
		}
		p := make([]byte, 32)
		binary.LittleEndian.PutUint32(p, offered|mysqlSSL)
		binary.LittleEndian.PutUint32(p[4:], uint32(g.cfg.MaxMessageBytes))
		p[8] = greeting[charset]
		if g.writeFrame(ctx, up, mysqlPacket(1, p)) != nil {
			return c, up, nil, 0, errFrame
		}
		tc := tls.Client(up, g.originTLS)
		tc.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
		if tc.HandshakeContext(ctx) != nil {
			return c, up, nil, 0, errFrame
		}
		up = tc
		upSeq = 2
	}
	if g.serverTLS == nil {
		offered &^= mysqlSSL
	} else {
		offered |= mysqlSSL
	}
	mysqlSetCaps(greeting, lo, hi, offered)
	if g.writeFrame(ctx, c, mysqlPacket(0, greeting)) != nil {
		return c, up, nil, 0, errFrame
	}
	downSeq := byte(1)
	login, err := g.mysqlRead(ctx, c, downSeq, false)
	if err != nil || len(login) < 32 {
		return c, up, nil, 0, errFrame
	}
	flags := binary.LittleEndian.Uint32(login)
	if flags&mysqlSSL != 0 && g.serverTLS == nil {
		g.writeFrame(ctx, c, mysqlError(2))
		return c, up, nil, 0, errFrame
	}
	if flags&^offered != 0 {
		return c, up, nil, 0, errFrame
	}
	if flags&mysqlSSL != 0 {
		if g.serverTLS == nil || len(login) != 32 {
			return c, up, nil, 0, errFrame
		}
		tc := tls.Server(c, g.serverTLS)
		tc.SetDeadline(deadline(ctx, g.cfg.IOTimeout))
		if tc.HandshakeContext(ctx) != nil {
			return c, up, nil, 0, errFrame
		}
		c = tc
		downSeq++
		login, err = g.mysqlRead(ctx, c, downSeq, false)
		if err != nil || len(login) < 32 || binary.LittleEndian.Uint32(login) != flags {
			return c, up, nil, 0, errFrame
		}
	} else if g.serverTLS != nil {
		return c, up, nil, 0, errFrame
	}
	user, database, flags, ok := mysqlLogin(login)
	if !ok {
		return c, up, nil, 0, errFrame
	}
	attrs := map[string]string{"db.username": user, "db.database": database, "db.command": "AUTH"}
	if !g.allowed(event("mysql", "AUTH", ip, attrs)) {
		g.writeFrame(ctx, c, mysqlError(downSeq+1))
		return c, up, nil, 0, errFrame
	}
	upstreamFlags := flags &^ mysqlSSL
	if g.cfg.UpstreamTLS {
		upstreamFlags |= mysqlSSL
	}
	binary.LittleEndian.PutUint32(login, upstreamFlags)
	if g.writeFrame(ctx, up, mysqlPacket(upSeq, login)) != nil {
		return c, up, nil, 0, errFrame
	}
	upSeq++
	downSeq++
	for i := 0; i < 16; i++ {
		p, err := g.mysqlRead(ctx, up, upSeq, false)
		if err != nil || len(p) == 0 {
			return c, up, nil, 0, errFrame
		}
		upSeq++
		switch p[0] {
		case 0x00:
			if !mysqlTerminal(p, true) {
				return c, up, nil, 0, errFrame
			}
		case 0xff:
			if len(p) < 9 || p[3] != '#' {
				return c, up, nil, 0, errFrame
			}
		case 0xfe:
			plugin, salt, valid := pgCString(p[1:])
			if !valid || !mysqlAuthPlugin(plugin) || (len(salt) != 20 && (len(salt) != 21 || salt[20] != 0)) {
				return c, up, nil, 0, errFrame
			}
		case 0x01:
			if len(p) < 2 {
				return c, up, nil, 0, errFrame
			}
		default:
			return c, up, nil, 0, errFrame
		}
		if g.writeFrame(ctx, c, mysqlPacket(downSeq, p)) != nil {
			return c, up, nil, 0, errFrame
		}
		downSeq++
		if p[0] == 0 {
			return c, up, map[string]string{"db.username": user, "db.database": database}, flags, nil
		}
		if p[0] == 0xff {
			return c, up, nil, 0, errFrame
		}
		if p[0] == 1 && len(p) == 2 && p[1] == 3 {
			continue
		}
		opaque, err := g.mysqlRead(ctx, c, downSeq, false)
		if err != nil {
			return c, up, nil, 0, errFrame
		}
		downSeq++
		if g.writeFrame(ctx, up, mysqlPacket(upSeq, opaque)) != nil {
			return c, up, nil, 0, errFrame
		}
		upSeq++
	}
	return c, up, nil, 0, errFrame
}

func (s *mysqlConversation) prepare(deprecate bool) (uint32, int, bool, error) {
	b, err := s.read()
	if err != nil {
		return 0, 0, false, err
	}
	if b[0] == 0xff {
		return 0, 0, false, nil
	}
	if b[0] != 0 || len(b) != 12 || b[9] != 0 {
		return 0, 0, false, errFrame
	}
	id := binary.LittleEndian.Uint32(b[1:])
	columns, params := wordLE(b[5:7]), wordLE(b[7:9])
	if columns > s.g.cfg.MaxStateEntries || params > s.g.cfg.MaxStateEntries {
		return 0, 0, false, errFrame
	}
	for _, n := range []int{params, columns} {
		for i := 0; i < n; i++ {
			b, err = s.read()
			if err != nil || !mysqlColumn(b) {
				return 0, 0, false, errFrame
			}
		}
		if n > 0 && !deprecate {
			b, err = s.read()
			if err != nil || b[0] != 0xfe || !mysqlTerminal(b, false) {
				return 0, 0, false, errFrame
			}
		}
	}
	return id, params, true, nil
}
func wordLE(b []byte) int { return int(binary.LittleEndian.Uint16(b)) }

func (g *Gateway) mysqlClient(ctx context.Context, c net.Conn, ip string) {
	raw, err := g.dial(ctx)
	if err != nil {
		return
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	c, up, identity, flags, err := g.mysqlAuth(ctx, c, raw, ip)
	if err != nil {
		return
	}
	statements := map[uint32]mysqlStatement{}
	stateBytes := 0
	for i := 0; i < g.cfg.MaxSessionMessages; i++ {
		p, err := g.mysqlRead(ctx, c, 0, true)
		if err != nil || len(p) == 0 {
			return
		}
		command, query, database := "", "", identity["db.database"]
		_, databaseKnown := identity["db.database"]
		var id uint32
		var st mysqlStatement
		switch p[0] {
		case 0x01:
			if len(p) != 1 {
				return
			}
			command = "QUIT"
		case 0x02:
			if len(p) < 2 || len(p) > 257 || !cleanToken(string(p[1:])) {
				return
			}
			command = "INIT_DB"
			database = string(p[1:])
			databaseKnown = true
		case 0x03:
			command = "QUERY"
			query = string(p[1:])
		case 0x0e:
			if len(p) != 1 {
				return
			}
			command = "PING"
		case 0x16:
			command = "STMT_PREPARE"
			query = string(p[1:])
			if len(statements) >= g.cfg.MaxStateEntries || stateBytes+len(query)+len(database) > g.cfg.MaxMessageBytes {
				g.writeFrame(ctx, c, mysqlError(1))
				return
			}
		case 0x17, 0x19, 0x1a:
			if len(p) < 5 {
				return
			}
			id = binary.LittleEndian.Uint32(p[1:])
			var ok bool
			st, ok = statements[id]
			if !ok {
				g.writeFrame(ctx, c, mysqlError(1))
				return
			}
			query = st.query
			database, databaseKnown = st.database, st.databaseKnown
			switch p[0] {
			case 0x17:
				command = "STMT_EXECUTE"
				if len(p) < 10 || p[5] != 0 || binary.LittleEndian.Uint32(p[6:10]) != 1 {
					return
				}
				if st.parameters == 0 && len(p) != 10 {
					return
				}
				if st.parameters > 0 {
					off := 10 + (st.parameters+7)/8
					if len(p) <= off || p[off] > 1 {
						return
					}
					if p[off] == 1 && len(p) < off+1+2*st.parameters {
						return
					}
				}
			case 0x19:
				command = "STMT_CLOSE"
				if len(p) != 5 {
					return
				}
			case 0x1a:
				command = "STMT_RESET"
				if len(p) != 5 {
					return
				}
			}
		default:
			g.writeFrame(ctx, c, mysqlError(1))
			return
		}
		attrs := map[string]string{"db.command": command, "db.username": identity["db.username"]}
		if databaseKnown {
			attrs["db.database"] = database
		}
		if query != "" {
			attrs["db.query"] = query
		}
		if p[0] == 0x17 {
			attrs["db.statement_id"] = strconv.FormatUint(uint64(id), 10)
			attrs["db.parameter_count"] = strconv.Itoa(st.parameters)
		}
		if !g.allowed(event("mysql", command, ip, attrs)) {
			g.writeFrame(ctx, c, mysqlError(1))
			return
		}
		if g.writeFrame(ctx, up, mysqlPacket(0, p)) != nil {
			return
		}
		if p[0] == 0x01 {
			return
		}
		if p[0] == 0x19 {
			stateBytes -= len(st.query) + len(st.database)
			delete(statements, id)
			continue
		}
		responseCtx, cancel := context.WithTimeout(ctx, g.cfg.IOTimeout)
		conv := mysqlConversation{g: g, ctx: responseCtx, c: up, seq: 1}
		success := false
		if p[0] == 0x16 {
			var params int
			id, params, success, err = conv.prepare(flags&mysqlDeprecateEOF != 0)
			if err == nil && success {
				if _, exists := statements[id]; exists {
					cancel()
					return
				}
				statements[id] = mysqlStatement{query: query, parameters: params, database: database, databaseKnown: databaseKnown}
				stateBytes += len(query) + len(database)
			}
		} else {
			success, err = conv.result(flags&mysqlDeprecateEOF != 0, p[0] == 0x17)
		}
		cancel()
		if err != nil {
			g.writeFrame(ctx, c, mysqlError(1))
			return
		}
		if p[0] == 0x02 && success {
			identity["db.database"] = database
		}
		// SQL can change the default schema (USE, routines). Without interpreting
		// SQL, stop asserting session database state until a successful INIT_DB.
		if p[0] == 0x03 || p[0] == 0x17 {
			delete(identity, "db.database")
		}
		if g.writeFrame(ctx, c, conv.wire) != nil {
			return
		}
	}
}
