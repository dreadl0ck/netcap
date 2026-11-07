package networkdetect

import (
	"net/netip"
	"strconv"
	"strings"
)

const (
	ftpDataLifetimeNS = int64(60e9)
	maxFTPLine        = 512
	maxFTPCommands    = 8
)

type ftpTarget struct {
	port uint16
	at   int64
}

type ftpCommand struct {
	op     string
	target *ftpTarget
	grant  string
}

type ftpControl struct {
	client, clientIP, serverIP string
	accepted                   *ftpTarget
	pending                    []ftpCommand
	multiline                  int
}

type ftpDataGrant struct {
	owner string
	at    int64
}

func ftpDataKey(ev Event) string {
	return stableKey(ev.Scope, "ftp-data", ev.SrcIP, ev.DstIP, ev.DstPort)
}

func (e *Engine) negotiatedFTPData(ev Event, f *flow) bool {
	if f == nil {
		return false
	}
	if f.ftpData {
		return true // Same SYN sequence/incarnation, as checked by startFlow.
	}
	key := ftpDataKey(ev)
	grant, ok := e.ftpData[key]
	if !ok {
		return false
	}
	delete(e.ftpData, key) // One negotiated connection, never a source-port bypass.
	if ev.At-grant.at >= ftpDataLifetimeNS || e.flows[grant.owner] == nil {
		return false
	}
	f.ftpData = true
	return true
}

func (e *Engine) revokeFTP(owner string) {
	for key, grant := range e.ftpData {
		if grant.owner == owner {
			delete(e.ftpData, key)
		}
	}
}

func (e *Engine) disableFTP(owner string, f *flow) {
	e.revokeFTP(owner)
	f.ftp, f.ftpDisabled = nil, true
	for _, d := range f.directions {
		d.ftpLine = nil
	}
}

// Only contiguous, bounded control lines are consumed. A gap, oversized line,
// or unbounded pipelining disables exclusion for this control incarnation.
func (e *Engine) observeFTP(ev Event, f *flow, d *direction, payload []byte) {
	if f.ftpDisabled || f.ftpData {
		return
	}
	if f.ftp == nil {
		client, clientIP, serverIP := endpoint(ev.SrcIP, ev.SrcPort), ev.SrcIP, ev.DstIP
		switch {
		case ev.DstPort == 21:
		case ev.SrcPort == 21:
			client, clientIP, serverIP = endpoint(ev.DstIP, ev.DstPort), ev.DstIP, ev.SrcIP
		case f.client != "" && f.client != endpoint(ev.SrcIP, ev.SrcPort) &&
			strings.HasPrefix(string(d.prefix), "220 ") && strings.Contains(strings.ToUpper(string(d.prefix)), "FTP"):
			client, clientIP, serverIP = f.client, ev.DstIP, ev.SrcIP
		default:
			return
		}
		f.ftp = &ftpControl{client: client, clientIP: clientIP, serverIP: serverIP}
	}
	owner := flowKey(ev)
	for _, b := range payload {
		if len(d.ftpLine) >= maxFTPLine || b < 32 && b != '\r' && b != '\n' || b > 126 {
			e.disableFTP(owner, f)
			return
		}
		d.ftpLine = append(d.ftpLine, b)
		if b != '\n' {
			continue
		}
		if len(d.ftpLine) < 2 || d.ftpLine[len(d.ftpLine)-2] != '\r' {
			e.disableFTP(owner, f)
			return
		}
		line := string(d.ftpLine[:len(d.ftpLine)-2])
		d.ftpLine = d.ftpLine[:0]
		if endpoint(ev.SrcIP, ev.SrcPort) == f.ftp.client {
			e.ftpRequest(ev, owner, f, line)
		} else {
			e.ftpReply(ev, owner, f.ftp, line)
		}
		if f.ftpDisabled {
			return
		}
	}
}

func (e *Engine) ftpRequest(ev Event, owner string, f *flow, line string) {
	c := f.ftp
	if len(c.pending) >= maxFTPCommands {
		e.stats.Overflow++
		e.disableFTP(owner, f)
		return
	}
	op, arg, _ := strings.Cut(line, " ")
	op = strings.ToUpper(op)
	cmd := ftpCommand{op: op}
	switch op {
	case "PORT", "EPRT":
		c.accepted = nil
		e.revokeFTP(owner)
		if port, ok := ftpActiveTarget(op, arg, c.clientIP); ok {
			cmd.target = &ftpTarget{port: port, at: ev.At}
		}
	case "PASV", "EPSV", "AUTH", "QUIT", "REIN":
		c.accepted = nil
		e.revokeFTP(owner)
	case "RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD":
		if target := c.accepted; target != nil && ev.At-target.at < ftpDataLifetimeNS {
			data := Event{Scope: ev.Scope, SrcIP: c.serverIP, DstIP: c.clientIP, DstPort: target.port}
			key := ftpDataKey(data)
			if _, exists := e.ftpData[key]; !exists && len(e.ftpData) >= e.config.MaxFlows {
				e.stats.Overflow++
			} else {
				e.ftpData[key] = ftpDataGrant{owner: owner, at: ev.At}
				cmd.grant = key
			}
		}
		c.accepted = nil
	}
	c.pending = append(c.pending, cmd)
}

func (e *Engine) ftpReply(ev Event, owner string, c *ftpControl, line string) {
	if len(line) < 4 {
		return
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil || code < 100 || code > 599 {
		return
	}
	if c.multiline != 0 {
		if code != c.multiline || line[3] != ' ' {
			return
		}
		c.multiline = 0
	} else if line[3] == '-' {
		c.multiline = code
		return
	}
	if line[3] != ' ' || code < 200 || code == 220 || len(c.pending) == 0 {
		return
	}
	cmd := c.pending[0]
	c.pending = c.pending[1:]
	if port, ok := ftpPassiveTarget(cmd.op, code, line, c.serverIP); ok {
		// Passive clients commonly connect before issuing the transfer command.
		data := Event{Scope: ev.Scope, SrcIP: c.clientIP, DstIP: c.serverIP, DstPort: port}
		key := ftpDataKey(data)
		if _, exists := e.ftpData[key]; !exists && len(e.ftpData) >= e.config.MaxFlows {
			e.stats.Overflow++
		} else {
			e.ftpData[key] = ftpDataGrant{owner: owner, at: ev.At}
		}
	}
	if cmd.target != nil && code == 200 && ev.At-cmd.target.at < ftpDataLifetimeNS {
		c.accepted = &ftpTarget{port: cmd.target.port, at: ev.At}
	}
	if cmd.grant != "" && code >= 400 {
		delete(e.ftpData, cmd.grant)
	}
}

func ftpPassiveTarget(op string, code int, line, server string) (uint16, bool) {
	_, tuple, ok := strings.Cut(line, "(")
	if !ok {
		return 0, false
	}
	tuple, _, ok = strings.Cut(tuple, ")")
	if !ok {
		return 0, false
	}
	if op == "PASV" && code == 227 {
		return ftpActiveTarget("PORT", tuple, server)
	}
	if op != "EPSV" || code != 229 || len(tuple) < 5 || tuple[0] < 33 || tuple[0] > 126 {
		return 0, false
	}
	parts := strings.Split(tuple, tuple[:1])
	if len(parts) != 5 || parts[0] != "" || parts[1] != "" || parts[2] != "" || parts[4] != "" {
		return 0, false
	}
	port, err := strconv.ParseUint(parts[3], 10, 16)
	return uint16(port), err == nil && port > 0
}

func ftpActiveTarget(op, arg, client string) (uint16, bool) {
	var address string
	var port uint64
	if op == "PORT" {
		parts := strings.Split(arg, ",")
		if len(parts) != 6 {
			return 0, false
		}
		var bytes [6]uint64
		for i, p := range parts {
			n, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return 0, false
			}
			bytes[i] = n
		}
		address = netip.AddrFrom4([4]byte{byte(bytes[0]), byte(bytes[1]), byte(bytes[2]), byte(bytes[3])}).String()
		port = bytes[4]*256 + bytes[5]
	} else {
		if len(arg) < 5 || arg[0] < 33 || arg[0] > 126 {
			return 0, false
		}
		parts := strings.Split(arg, arg[:1])
		if len(parts) != 5 || parts[0] != "" || parts[4] != "" {
			return 0, false
		}
		a, err := netip.ParseAddr(parts[2])
		if err != nil || a.Zone() != "" || !(parts[1] == "1" && a.Is4() || parts[1] == "2" && a.Is6()) {
			return 0, false
		}
		address = a.Unmap().String()
		port, err = strconv.ParseUint(parts[3], 10, 16)
		if err != nil {
			return 0, false
		}
	}
	// Third-party/bounce destinations must remain visible to scan detection.
	return uint16(port), address == client && port > 0
}
