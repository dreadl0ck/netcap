package gateway

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
)

func respNumber(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, errFrame
	}
	s := string(b[1 : len(b)-2])
	n, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(n) != s {
		return 0, errFrame
	}
	return n, nil
}
func readRESP(r *bufio.Reader, limit, depth int) ([]byte, error) {
	if depth > 16 || limit < 3 {
		return nil, errFrame
	}
	line, err := boundedLine(r, limit)
	if err != nil {
		return nil, err
	}
	n := 0
	switch line[0] {
	case '+', '-', ':':
		return line, nil
	case '$', '*':
		n, err = respNumber(line)
		if err != nil || n < -1 {
			return nil, errFrame
		}
	default:
		return nil, errFrame
	}
	if n == -1 {
		return line, nil
	}
	if line[0] == '$' {
		if n > limit-len(line)-2 {
			return nil, errFrame
		}
		b := make([]byte, n+2)
		if _, err = io.ReadFull(r, b); err != nil {
			return nil, err
		}
		if !bytes.HasSuffix(b, []byte("\r\n")) {
			return nil, errFrame
		}
		return append(line, b...), nil
	}
	if n > (limit-len(line))/3 {
		return nil, errFrame
	}
	out := line
	for i := 0; i < n; i++ {
		b, err := readRESP(r, limit-len(out), depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
func redisArgs(b []byte) ([][]byte, error) {
	r := bufio.NewReader(bytes.NewReader(b))
	line, err := boundedLine(r, len(b))
	if err != nil || line[0] != '*' {
		return nil, errFrame
	}
	n, err := respNumber(line)
	if err != nil || n < 1 || n > 1024 {
		return nil, errFrame
	}
	args := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		line, err = boundedLine(r, len(b))
		if err != nil || line[0] != '$' {
			return nil, errFrame
		}
		size, err := respNumber(line)
		if err != nil || size < 0 || size > len(b) {
			return nil, errFrame
		}
		v := make([]byte, size+2)
		if _, err = io.ReadFull(r, v); err != nil || !bytes.HasSuffix(v, []byte("\r\n")) {
			return nil, errFrame
		}
		args = append(args, v[:size])
	}
	return args, nil
}
func redisWord(b []byte) string {
	if len(b) == 0 || len(b) > 64 {
		return ""
	}
	for _, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return ""
		}
	}
	return strings.ToUpper(string(b))
}

func redisIdentity(cmd string, args [][]byte, current string) (string, bool) {
	if cmd == "AUTH" {
		if len(args) == 2 {
			return "default", true
		}
		if len(args) == 3 {
			return string(args[1]), true
		}
		return "", false
	}
	if cmd != "HELLO" {
		return current, true
	}
	if len(args) < 2 || string(args[1]) != "2" {
		return "", false
	}
	auth, named := false, false
	for i := 2; i < len(args); {
		switch redisWord(args[i]) {
		case "AUTH":
			if auth || i+2 >= len(args) {
				return "", false
			}
			auth = true
			current = string(args[i+1])
			i += 3
		case "SETNAME":
			if named || i+1 >= len(args) {
				return "", false
			}
			named = true
			i += 2
		default:
			return "", false
		}
	}
	return current, true
}
func (g *Gateway) redisClient(ctx context.Context, c net.Conn, ip string) {
	r := bufio.NewReaderSize(c, 4096)
	var up net.Conn
	var ur *bufio.Reader
	database := "0"
	username := "default"
	for i := 0; i < g.cfg.MaxSessionMessages; i++ {
		c.SetReadDeadline(deadline(ctx, g.cfg.IdleTimeout))
		if _, err := r.Peek(1); err != nil {
			return
		}
		c.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
		b, err := readRESP(r, g.cfg.MaxMessageBytes, 0)
		if err != nil {
			return
		}
		args, err := redisArgs(b)
		if err != nil {
			return
		}
		cmd := redisWord(args[0])
		if cmd == "" {
			return
		}
		// Transactions, pushes, replication and protocol upgrades need different reply
		// ownership. Reject and close before origin rather than risk stream desync.
		switch cmd {
		case "MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "MONITOR", "SYNC", "PSYNC", "REPLCONF", "RESET":
			g.writeFrame(ctx, c, []byte("-ERR unsupported gateway session mode\r\n"))
			return
		}
		if cmd == "HELLO" && (len(args) < 2 || string(args[1]) != "2") {
			g.writeFrame(ctx, c, []byte("-ERR RESP3 unsupported\r\n"))
			return
		}
		candidate, ok := redisIdentity(cmd, args, username)
		if !ok {
			g.writeFrame(ctx, c, []byte("-ERR malformed session command\r\n"))
			return
		}
		if cmd == "CLIENT" && len(args) > 1 {
			switch redisWord(args[1]) {
			case "REPLY", "TRACKING", "CACHING":
				g.writeFrame(ctx, c, []byte("-ERR unsupported gateway reply mode\r\n"))
				return
			}
		}
		a := map[string]string{"db.command": cmd, "db.database": database, "db.username": candidate, "db.scope": "command"}
		switch cmd {
		case "FLUSHALL", "CONFIG", "ACL", "MODULE", "SHUTDOWN", "DEBUG", "REPLICAOF", "SLAVEOF", "CLUSTER", "SAVE", "BGSAVE", "BGREWRITEAOF":
			a["db.scope"] = "server"
		case "FLUSHDB", "KEYS", "SCAN", "RANDOMKEY", "DBSIZE", "SWAPDB":
			a["db.scope"] = "database"
		case "EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO", "FUNCTION", "SCRIPT":
			a["db.scope"] = "script"
		case "AUTH", "HELLO", "SELECT", "CLIENT", "QUIT":
			a["db.scope"] = "session"
		}
		if cmd == "CLIENT" && len(args) > 1 {
			switch redisWord(args[1]) {
			case "KILL", "PAUSE", "UNPAUSE", "UNBLOCK":
				a["db.scope"] = "server"
			}
		}
		switch cmd {
		case "ACL", "CLIENT", "CLUSTER", "CONFIG", "COMMAND", "FUNCTION", "SCRIPT", "XGROUP", "XINFO", "MEMORY", "MODULE", "LATENCY":
			if len(args) > 1 {
				a["db.subcommand"] = redisWord(args[1])
			}
		}
		// Values, AUTH/HELLO passwords and scripts never enter the event or logs.
		if !g.allowed(event("redis", cmd, ip, a)) {
			g.writeFrame(ctx, c, []byte("-NOPERM blocked by gateway\r\n"))
			return
		}
		if up == nil {
			up, err = g.dial(ctx)
			if err != nil {
				return
			}
			defer up.Close()
			stop := context.AfterFunc(ctx, func() { up.Close() })
			defer stop()
			ur = bufio.NewReaderSize(up, 4096)
		}
		if g.writeFrame(ctx, up, b) != nil {
			return
		}
		up.SetReadDeadline(deadline(ctx, g.cfg.IOTimeout))
		resp, err := readRESP(ur, g.cfg.MaxMessageBytes, 0)
		if err != nil {
			return
		}
		if cmd == "SELECT" && len(args) == 2 && resp[0] != '-' {
			database = string(args[1])
		}
		if resp[0] != '-' {
			username = candidate
		}
		if g.writeFrame(ctx, c, resp) != nil {
			return
		}
	}
}
