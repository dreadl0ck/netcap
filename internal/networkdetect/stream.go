package networkdetect

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

type direction struct {
	next      uint32
	started   bool
	prefix    []byte
	prefixSeq uint32
	bytes     uint64
	gap       bool
	ftpLine   []byte
}
type flow struct {
	synSequence   uint32
	client        string
	first         int64
	last          int64
	directions    map[string]*direction
	ssh           bool
	ftp           *ftpControl
	ftpDisabled   bool
	ftpData       bool
	serverSynSeen bool
	serverISN     uint32
}

func endpoint(ip string, port uint16) string { return fmt.Sprintf("%s/%d", ip, port) }
func flowKey(ev Event) string {
	a, b := endpoint(ev.SrcIP, ev.SrcPort), endpoint(ev.DstIP, ev.DstPort)
	if a > b {
		a, b = b, a
	}
	scope := ev.Scope
	data, _ := json.Marshal(scope)
	return string(data) + "|" + a + "|" + b
}
func (e *Engine) startFlow(ev Event) *flow {
	key := flowKey(ev)
	if f, ok := e.flows[key]; ok {
		if ev.At-f.last <= e.config.WindowNS && f.synSequence == ev.Seq && f.client == endpoint(ev.SrcIP, ev.SrcPort) {
			return f
		}
		e.revokeFTP(key)
		delete(e.flows, key)
	}
	if len(e.flows) >= e.config.MaxFlows {
		e.stats.Overflow++
		return nil
	}
	e.flows[key] = &flow{synSequence: ev.Seq, client: endpoint(ev.SrcIP, ev.SrcPort), first: ev.At, last: ev.At, directions: map[string]*direction{endpoint(ev.SrcIP, ev.SrcPort): {next: ev.Seq + 1, started: true}}}
	return e.flows[key]
}

func (e *Engine) observeStream(ev Event, add func(string, string, string, string, uint64, uint64, []string, int64, *Indicator, ...string)) {
	key := flowKey(ev)
	f := e.flows[key]
	if f != nil && ev.At-f.last > e.config.WindowNS {
		e.revokeFTP(key)
		delete(e.flows, key)
		f = nil
	}
	if f == nil {
		if len(e.flows) >= e.config.MaxFlows {
			e.stats.Overflow++
			return
		}
		f = &flow{first: ev.At, last: ev.At, directions: map[string]*direction{}}
		e.flows[key] = f
	}
	f.last = ev.At
	source := endpoint(ev.SrcIP, ev.SrcPort)
	d := f.directions[source]
	if d == nil {
		d = &direction{}
		f.directions[source] = d
	}
	if !d.started {
		d.next = ev.Seq
		d.prefixSeq = ev.Seq
		d.started = true
	}
	if len(d.prefix) == 0 {
		d.prefixSeq = d.next
	}
	delta := int32(ev.Seq - d.next)
	if delta > 0 {
		if !d.gap {
			e.stats.StreamGaps++
		}
		d.gap = true
		e.disableFTP(key, f)
		return
	}
	payload := ev.Payload
	if delta < 0 {
		start := int64(int32(ev.Seq - d.prefixSeq))
		begin := max(int64(0), -start)
		end := min(int64(len(ev.Payload)), int64(len(d.prefix))-start, -int64(delta))
		conflicts := uint64(0)
		for i := begin; i < end; i++ {
			if ev.Payload[i] != d.prefix[start+i] {
				conflicts++
			}
		}
		if conflicts > 0 {
			e.stats.ConflictingOverlaps++
			e.stats.ConflictingOverlapBytes += conflicts
			add("tcp.overlap-conflict", "behavioral-suspicion", "medium", "T1557", conflicts, 1, []string{"Different bytes at already observed TCP sequence positions within the retained 4096-byte prefix"}, f.first, nil, "First-arrival decoding is retained; packet evidence is needed to determine which bytes the endpoint accepted")
		}
		skip := -int64(delta)
		if skip >= int64(len(payload)) {
			return
		}
		payload = payload[skip:]
	}
	d.next += uint32(len(payload))
	d.bytes += uint64(len(payload))
	if len(d.prefix) < 4096 {
		n := 4096 - len(d.prefix)
		if n > len(payload) {
			n = len(payload)
		}
		d.prefix = append(d.prefix, payload[:n]...)
	}
	if d.gap {
		return
	}
	e.observeFTP(ev, f, d, payload)
	text := string(d.prefix)
	if strings.HasPrefix(text, "SSH-2.0-") || strings.HasPrefix(text, "SSH-1.99-") {
		if strings.Contains(text, "\n") {
			f.ssh = true
			port := ev.DstPort
			if source != f.client && f.client != "" {
				port = ev.SrcPort
			}
			if port != 22 && ev.SrcPort != 22 && ev.DstPort != 22 && f.client != "" {
				add("ssh.nonstandard-port", "behavioral-suspicion", "medium", "T1571", uint64(port), 22, []string{"SSH version banner"}, f.first, nil, "SSH service identification does not establish exfiltration")
			}
		}
	}
	if f.ssh && source == f.client && d.bytes >= e.config.SSHBytes {
		add("ssh.large-upload", "behavioral-suspicion", "medium", "T1048.002", d.bytes, e.config.SSHBytes, []string{"Unique contiguous client TCP payload bytes"}, f.first, nil, "Encrypted content and authorization are unavailable; configured source exceptions apply")
	}
	for _, line := range strings.Split(text, "\n") {
		var request struct {
			Method string `json:"method"`
		}
		if json.Unmarshal([]byte(line), &request) == nil && request.Method == "mining.subscribe" {
			add("protocol.stratum", "policy-observation", "medium", "T1496", 1, 1, []string{"mining.subscribe"}, f.first, nil, "Mining protocol activity does not establish unauthorized mining")
			break
		}
	}
	nick, user := false, false
	for _, line := range strings.Split(text, "\n") {
		nick = nick || strings.HasPrefix(line, "NICK ")
		user = user || strings.HasPrefix(line, "USER ")
	}
	if nick && user {
		add("protocol.irc", "policy-observation", "info", "", 1, 1, []string{"IRC NICK and USER commands"}, f.first, nil, "IRC is also used legitimately")
	}
	tlsRecord := len(d.prefix) >= 5 && d.prefix[0] >= 20 && d.prefix[0] <= 23 && d.prefix[1] == 3 && d.prefix[2] <= 4 && binary.BigEndian.Uint16(d.prefix[3:5]) <= 18432
	sslV2 := len(d.prefix) >= 11 && d.prefix[0]&0x80 != 0 && d.prefix[2] == 1 && (d.prefix[3] == 3 || d.prefix[3] == 0 && d.prefix[4] == 2)
	if source == f.client && d.bytes >= 128 && ev.DstPort == 443 && !tlsRecord && !sslV2 && !f.ssh {
		add("policy.non-tls-on-443", "policy-observation", "low", "T1571", d.bytes, 128, []string{"At least 128 contiguous TCP payload bytes whose prefix is not a TLS record"}, f.first, nil, "A non-TLS prefix on TCP/443 can be intentional or precede a protocol upgrade; C2 intent is not established")
	}
	if len(d.prefix) >= 64 && (ev.DstPort == 21 || ev.DstPort == 23 || ev.DstPort == 110 || ev.DstPort == 143 || ev.DstPort == 873) && !f.ssh && !tlsRecord {
		add("policy.cleartext-service", "policy-observation", "low", "", uint64(len(d.prefix)), 64, []string{fmt.Sprintf("TCP destination port %d", ev.DstPort)}, f.first, nil, "Port and observed payload do not identify the application protocol or prove credentials were sent")
	}
}
