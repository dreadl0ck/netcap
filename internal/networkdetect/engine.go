package networkdetect

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/dreadl0ck/netcap/types"
)

type Scope struct {
	Sensor    string   `json:"sensor"`
	Interface string   `json:"interface"`
	VLANs     []uint16 `json:"vlans,omitempty"`
}

// Event is capture-derived; fixture scenario labels are never detector inputs.
type Event struct {
	Ack     uint32 `json:"ack,omitempty"`
	At      int64  `json:"at"`
	Scope   Scope  `json:"scope"`
	Kind    string `json:"kind"`
	SrcIP   string `json:"srcIP"`
	DstIP   string `json:"dstIP"`
	SrcPort uint16 `json:"srcPort,omitempty"`
	DstPort uint16 `json:"dstPort,omitempty"`
	Name    string `json:"name,omitempty"`
	QType   uint16 `json:"qType,omitempty"`
	Seq     uint32 `json:"seq,omitempty"`
	Payload []byte `json:"payload,omitempty"`
}

type Evidence struct {
	Schema         int        `json:"schema"`
	Detector       string     `json:"detector"`
	Classification string     `json:"classification"`
	Scope          Scope      `json:"scope"`
	FirstSeen      int64      `json:"firstSeen"`
	LastSeen       int64      `json:"lastSeen"`
	Observed       uint64     `json:"observed"`
	Threshold      uint64     `json:"threshold"`
	WindowNS       int64      `json:"windowNS"`
	Samples        []string   `json:"samples"`
	Limitations    []string   `json:"limitations"`
	Indicator      *Indicator `json:"indicator,omitempty"`
}

type Stats struct {
	ConflictingOverlaps     uint64 `json:"conflictingOverlaps,omitempty"`
	ConflictingOverlapBytes uint64 `json:"conflictingOverlapBytes,omitempty"`
	Matches                 uint64 `json:"matches"`
	PendingAggregates       int    `json:"pendingAggregates"`
	CapacityFlushes         uint64 `json:"capacityFlushes"`
	FTPDataExclusions       uint64 `json:"ftpDataExclusions"`
	SMTPRelayExclusions     uint64 `json:"smtpRelayExclusions"`
	AggregationMode         string `json:"aggregationMode,omitempty"`
	ApplicationMode         string `json:"applicationMode,omitempty"`
	ApplicationAlerts       uint64 `json:"applicationAlerts,omitempty"`
	ApplicationQueuedBytes  int64  `json:"applicationQueuedBytes,omitempty"`
	ApplicationPeakBytes    int64  `json:"applicationPeakBytes,omitempty"`
	ApplicationQueueLimit   int64  `json:"applicationQueueLimit,omitempty"`
	ApplicationQueueDrops   uint64 `json:"applicationQueueDrops,omitempty"`
	ApplicationLate         uint64 `json:"applicationLate,omitempty"`
	Schema                  int    `json:"schema"`
	Events                  uint64 `json:"events"`
	Alerts                  uint64 `json:"alerts"`
	Overflow                uint64 `json:"overflow"`
	Late                    uint64 `json:"late"`
	StreamGaps              uint64 `json:"streamGaps"`
	Keys                    int    `json:"keys"`
	Flows                   int    `json:"flows"`
	Indicators              int    `json:"indicators"`
	Error                   string `json:"error,omitempty"`
}

type window struct {
	first  int64
	last   int64
	values map[string]int64
}

type Engine struct {
	config     Config
	windows    map[string]*window
	aggregates *aggregator
	flows      map[string]*flow
	ftpData    map[string]ftpDataGrant
	beacons    map[string]*beacon
	watermark  int64
	lastSweep  int64
	observed   bool
	stats      Stats
}

func New(c Config) (*Engine, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(c)
	_ = json.Unmarshal(data, &c)
	for n := range c.Indicators {
		if c.Indicators[n].Kind == "ip" {
			addr, _ := netip.ParseAddr(c.Indicators[n].Value)
			c.Indicators[n].Value = addr.Unmap().String()
		}
	}
	return &Engine{config: c, windows: map[string]*window{}, aggregates: newAggregator(c), flows: map[string]*flow{}, ftpData: map[string]ftpDataGrant{}, beacons: map[string]*beacon{}, stats: Stats{Schema: 1, Indicators: len(c.Indicators), AggregationMode: "capture-time windows; live checkpoints emit partial windows", ApplicationMode: "sorted record replay at end of capture"}}, nil
}

func (e *Engine) Stats() Stats {
	s := e.stats
	s.Keys = len(e.windows)
	s.Flows = len(e.flows)
	s.Matches = e.aggregates.matches
	s.PendingAggregates = len(e.aggregates.pending)
	s.CapacityFlushes = e.aggregates.capacity
	return s
}

// Flush finalizes pending matches at EOF/shutdown; repeated calls emit nothing.
func (e *Engine) Flush() []*types.Alert {
	alerts := e.aggregates.flush()
	e.stats.Alerts += uint64(len(alerts))
	return alerts
}

// Checkpoint emits pending live matches without moving the event watermark.
// Rows across checkpoints retain their AggregateKey and disjoint match counts.
func (e *Engine) Checkpoint() []*types.Alert {
	alerts := e.aggregates.checkpoint("live")
	e.stats.Alerts += uint64(len(alerts))
	return alerts
}

func (e *Engine) Observe(ev Event) (alerts []*types.Alert, err error) {
	if ev.At < 0 || ev.Scope.Sensor == "" || ev.Scope.Interface == "" || len(ev.Scope.Sensor) > 256 || len(ev.Scope.Interface) > 256 || len(ev.Scope.VLANs) > 4 || len(ev.Payload) > 65535 || len(ev.Name) > 253 {
		return nil, errors.New("invalid bounded capture event")
	}
	for _, vlan := range ev.Scope.VLANs {
		if vlan > 4095 {
			return nil, errors.New("invalid VLAN")
		}
	}
	for _, ip := range []*string{&ev.SrcIP, &ev.DstIP} {
		addr, err := netip.ParseAddr(*ip)
		if err != nil || addr.Zone() != "" {
			return nil, errors.New("invalid event IP")
		}
		*ip = addr.Unmap().String()
	}
	e.stats.Events++
	if e.observed && ev.At < e.watermark {
		e.stats.Late++
		return nil, nil
	}
	if !e.observed || ev.At > e.watermark {
		e.watermark = ev.At
		if !e.observed || ev.At-e.lastSweep >= 1e9 {
			e.expire(ev.At)
			e.lastSweep = ev.At
		}
	}
	e.observed = true
	alerts = e.aggregates.advance(ev.At)
	defer func() { e.stats.Alerts += uint64(len(alerts)) }()
	for _, s := range e.config.ApprovedSources {
		a, _ := netip.ParseAddr(ev.SrcIP)
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
			return alerts, nil
		}
		if allowed, err := netip.ParseAddr(s); err == nil && allowed.Unmap() == a {
			return alerts, nil
		}
	}
	group := ""
	add := func(detector, class, severity, mitre string, count, threshold uint64, samples []string, first int64, indicator *Indicator, limitations ...string) {
		key := stableKey(ev.Scope, ev.SrcIP, detector, class, ev.DstIP, ev.Name, indicator)
		if detector == "smtp.fanout" {
			key = stableKey(ev.Scope, ev.SrcIP, detector, e.networkRole(ev.DstIP))
		}
		if detector == "network.scan" {
			key = stableKey(ev.Scope, ev.SrcIP, detector, group)
		}
		if detector == "c2.beacon" {
			key = stableKey(ev.Scope, ev.SrcIP, detector, "tcp", ev.DstIP, ev.DstPort)
		}
		if samples == nil {
			samples = []string{}
		}
		if limitations == nil {
			limitations = []string{}
		}
		window := e.config.WindowNS
		if detector == "c2.beacon" {
			window = e.config.BeaconWindowNS
		}
		evidence := Evidence{1, detector, class, ev.Scope, first, ev.At, count, threshold, window, samples, limitations, indicator}
		data, _ := json.Marshal(evidence)
		alert := &types.Alert{Timestamp: ev.At, Name: detector, RuleName: detector, Description: detector + ": " + class, RecordType: "NetworkDetection", Severity: severity, SrcIP: ev.SrcIP, DstIP: ev.DstIP, SrcPort: fmt.Sprint(ev.SrcPort), DstPort: fmt.Sprint(ev.DstPort), Domain: ev.Name, MITRE: mitre, Tags: []string{"network-detection", class}, MatchedRecord: string(data)}
		alerts = append(alerts, e.aggregates.add(key, alert)...)
	}
	if ev.Kind == "dns" {
		ev.Name = strings.ToLower(strings.TrimSuffix(ev.Name, "."))
		if !validDomain(ev.Name) {
			return alerts, nil
		}
	}
	if ev.Kind == "dns" || ev.Kind == "syn" {
		for n := range e.config.Indicators {
			i := &e.config.Indicators[n]
			if ev.At < i.ValidFrom || ev.At >= i.ValidUntil {
				continue
			}
			match := i.Kind == "ip" && ev.Kind == "syn" && ev.DstIP == i.Value || i.Kind == "domain" && ev.Kind == "dns" && domainMatch(ev.Name, i.Value)
			if match {
				severity := "medium"
				if i.Category == "c2" {
					severity = "high"
				}
				add("intel."+i.Category, "indicator-match", severity, "", 1, 1, []string{i.Value}, ev.At, i, "Indicator association does not establish execution or compromise")
			}
		}
	}
	switch ev.Kind {
	case "dns":
		label, parent, _ := strings.Cut(ev.Name, ".")
		if encoded, zone, suspicious := dnsTunnelPayload(ev.Name, ev.QType); suspicious {
			count, first, samples := e.count(ev, "dns-tunnel|"+zone, encoded)
			if count >= e.config.DNSNames {
				ev.Name = zone
				add("dns.tunnel", "behavioral-suspicion", "medium", "T1071.004", uint64(count), uint64(e.config.DNSNames), samples, first, nil, "Encoded query-name diversity also occurs in legitimate services; the observed source may be a DNS forwarder")
			}
		}
		digits := strings.ContainsAny(label, "0123456789")
		if !strings.Contains(parent, ".") && len(label) >= 7 && len(label) <= 20 && digits && entropy([]byte(label)) >= 2.5 {
			count, first, samples := e.count(ev, "dns-dga", ev.Name)
			if count >= e.config.DNSNames {
				ev.Name = ""
				add("dns.dga", "behavioral-suspicion", "medium", "T1568.002", uint64(count), uint64(e.config.DNSNames), samples, first, nil, "Lexical/domain-diversity heuristic; DNS response outcomes are not required or inferred")
			}
		}
		if ev.Name == "api.telegram.org" {
			add("policy.telegram-api", "policy-observation", "info", "", 1, 1, []string{ev.Name}, ev.At, nil, "Encrypted traffic does not reveal bot method, token or intent")
		}
		for _, suffix := range []string{"interact.sh", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "oastify.com", "burpcollaborator.net"} {
			if domainMatch(ev.Name, suffix) {
				add("policy.oast", "policy-observation", "low", "", 1, 1, []string{ev.Name}, ev.At, nil, "Authorized application testing also uses OAST")
				break
			}
		}
	case "syn":
		f := e.startFlow(ev)
		if e.negotiatedFTPData(ev, f) {
			e.stats.FTPDataExclusions++
			break
		}
		relay, role := e.smtpRole(ev)
		relay = relay && ev.DstPort == 25
		if relay {
			e.stats.SMTPRelayExclusions++
		}
		// Count scan shapes, not the union of normal web destinations.
		group = "scan-vertical|" + ev.DstIP
		count, first, samples := e.count(ev, group, fmt.Sprint(ev.DstPort))
		if count >= e.config.ScanTargets {
			add("network.scan", "behavioral-suspicion", "medium", "T1046", uint64(count), uint64(e.config.ScanTargets), samples, first, nil, "Distinct ports on one host; outcomes and intent are not inferred")
		}
		if ev.DstPort != 80 && ev.DstPort != 443 && !relay {
			group = fmt.Sprintf("scan-horizontal|%d", ev.DstPort)
			count, first, samples = e.count(ev, group, ev.DstIP)
			if count >= e.config.ScanTargets {
				limits := []string{"Distinct hosts on one non-web port; outcomes and intent are not inferred"}
				if ev.DstPort == 25 {
					limits = append(limits, role)
				}
				add("network.scan", "behavioral-suspicion", "medium", "T1046", uint64(count), uint64(e.config.ScanTargets), samples, first, nil, limits...)
			}
		}
		if ev.DstPort == 25 && !relay {
			count, first, samples := e.count(ev, "smtp", ev.DstIP)
			if count >= e.config.SMTPHosts {
				add("smtp.fanout", "behavioral-suspicion", "medium", "", uint64(count), uint64(e.config.SMTPHosts), samples, first, nil, "Mail relays can legitimately contact many SMTP servers", role)
			}
		}
		e.observeBeacon(ev, add)
	case "icmp":
		group = "icmp-discovery"
		count, first, samples := e.count(ev, group, ev.DstIP)
		if count >= e.config.ScanTargets {
			add("network.scan", "behavioral-suspicion", "low", "T1018", uint64(count), uint64(e.config.ScanTargets), samples, first, nil, "Distinct ICMP echo destinations indicate discovery; authorization and intent are unknown")
		}
		if len(ev.Payload) >= 1024 && entropy(ev.Payload) >= 6 {
			count, first, samples := e.count(ev, "icmp|"+ev.DstIP, fmt.Sprint(ev.Seq))
			if count >= e.config.ICMPEchoes {
				add("icmp.tunnel", "behavioral-suspicion", "medium", "T1048.003", uint64(count), uint64(e.config.ICMPEchoes), samples, first, nil, "Large randomized diagnostic echoes can look similar")
			}
		}
	case "data":
		e.observeStream(ev, add)
	case "synack":
		if f := e.flows[flowKey(ev)]; f != nil && f.client != "" && ev.Ack == f.synSequence+1 {
			if f.serverSynSeen && f.serverISN != ev.Seq {
				add("tcp.synack-conflict", "behavioral-suspicion", "medium", "T1557", 1, 1, []string{"Competing SYN-ACK sequence numbers for one observed client SYN"}, f.first, nil, "A race, middlebox or capture artifact can also produce competing handshakes; endpoint acceptance is not inferred")
			}
			f.serverSynSeen, f.serverISN = true, ev.Seq
		}
	case "end":
		e.revokeFTP(flowKey(ev))
		delete(e.flows, flowKey(ev))
	case "refused":
		if f := e.flows[flowKey(ev)]; f != nil && f.ftpData && ev.At-f.last <= e.config.WindowNS {
			break
		}
		if relay, _ := e.smtpRole(ev); relay && ev.DstPort == 25 {
			break
		}
		group = fmt.Sprintf("scan-refused|%d", ev.DstPort)
		count, first, samples := e.count(ev, group, ev.DstIP)
		if count >= e.config.ScanTargets {
			add("network.scan", "behavioral-suspicion", "medium", "T1046", uint64(count), uint64(e.config.ScanTargets), samples, first, nil, "Distinct hosts refusing TCP connections; authorization and intent are unknown")
		}
	default:
		return alerts, errors.New("unknown capture event kind")
	}
	return alerts, nil
}

func domainMatch(name, suffix string) bool {
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}
func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var h float64
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(data))
			h -= p * math.Log2(p)
		}
	}
	return h
}
func (e *Engine) key(ev Event, purpose string) string {
	scope, _ := json.Marshal(ev.Scope)
	return string(scope) + "|" + ev.SrcIP + "|" + purpose
}
func (e *Engine) count(ev Event, purpose, value string) (int, int64, []string) {
	key := e.key(ev, purpose)
	w := e.windows[key]
	if w == nil {
		if len(e.windows) >= e.config.MaxKeys {
			e.stats.Overflow++
			return 0, ev.At, nil
		}
		w = &window{first: ev.At, values: map[string]int64{}}
		e.windows[key] = w
	}
	w.last = ev.At
	for v, at := range w.values {
		if ev.At-at > e.config.WindowNS {
			delete(w.values, v)
		}
	}
	if len(w.values) >= 128 {
		if _, ok := w.values[value]; !ok {
			e.stats.Overflow++
			return len(w.values), w.first, nil
		}
	}
	w.values[value] = ev.At
	first := ev.At
	samples := make([]string, 0, len(w.values))
	for v, at := range w.values {
		samples = append(samples, v)
		if at < first {
			first = at
		}
	}
	sort.Strings(samples)
	if len(samples) > 8 {
		samples = samples[:8]
	}
	return len(w.values), first, samples
}
func (e *Engine) expire(at int64) {
	for k, w := range e.windows {
		if at-w.last > e.config.WindowNS {
			delete(e.windows, k)
		}
	}
	for k, f := range e.flows {
		if at-f.last > e.config.WindowNS {
			e.revokeFTP(k)
			delete(e.flows, k)
		}
	}
	for k, grant := range e.ftpData {
		if at-grant.at >= ftpDataLifetimeNS {
			delete(e.ftpData, k)
		}
	}
	e.expireBeacons(at)
}
