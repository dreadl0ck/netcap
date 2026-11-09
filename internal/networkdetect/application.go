package networkdetect

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type ApplicationObservation struct {
	RangeTransfer                                  bool
	DecryptedTLS                                   bool
	At                                             int64
	Scope                                          Scope
	Kind, SrcIP, DstIP                             string
	SrcPort, DstPort                               uint16
	Method, Path, Host, CommunityID, Qualification string
	Status                                         int
	Executable                                     bool
}

func Observation(m proto.Message) (ApplicationObservation, bool) {
	var o ApplicationObservation
	switch r := m.(type) {
	case *types.HTTP:
		if r.Method == "" {
			return o, false
		}
		o = ApplicationObservation{At: r.Timestamp, Kind: "http", SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: uint16(r.SrcPort), DstPort: uint16(r.DstPort), Method: r.Method, Path: r.URL, Host: r.Host, Status: int(r.StatusCode), CommunityID: r.CommunityID, Qualification: r.ReassemblyStatus}
		o.RangeTransfer = r.StatusCode == 206
		for _, q := range r.ParseQualifications {
			if q == "decrypted-tls-key-log" {
				o.DecryptedTLS = true
			}
		}
		for _, header := range r.RequestHeaders {
			if strings.EqualFold(string(header.Name), "Range") {
				o.RangeTransfer = true
			}
		}
	case *types.File:
		if r.Protocol != "HTTP" || !(r.IsPEExecutable || r.IsELFExecutable || r.IsMachO) {
			return o, false
		}
		o = ApplicationObservation{At: r.Timestamp, Kind: "executable", SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: uint16(r.SrcPort), DstPort: uint16(r.DstPort), CommunityID: r.CommunityID, Executable: true}
	case *types.SMB:
		if r.Username == "" || r.NTLMVersion == "" || r.IsEncrypted || !strings.Contains(r.CommandName, "SESSION_SETUP") {
			return o, false
		}
		o = ApplicationObservation{At: r.Timestamp, Kind: "ntlm", SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: uint16(r.SrcPort), DstPort: uint16(r.DstPort), CommunityID: r.CommunityID}
		if r.IsResponse {
			o.SrcIP, o.DstIP = o.DstIP, o.SrcIP
			o.SrcPort, o.DstPort = o.DstPort, o.SrcPort
		}
	case *types.DCERPC:
		if r.PacketType != 0 || r.InterfaceUUID == "" {
			return o, false
		}
		o = ApplicationObservation{At: r.Timestamp, Kind: "rpc", SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: uint16(r.SrcPort), DstPort: uint16(r.DstPort), Method: strings.ToLower(r.InterfaceUUID), Path: r.OperationName, Status: int(r.OpNum), CommunityID: r.CommunityID}
	case *types.Kerberos:
		if r.MessageTypeCode != 10 || r.ClientName == "" || strings.HasSuffix(r.ClientName, "$") {
			return o, false
		}
		o = ApplicationObservation{At: r.Timestamp, Kind: "kerberos", SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: uint16(r.SrcPort), DstPort: uint16(r.DstPort), Method: "AS-REQ", Path: r.ClientName, CommunityID: r.CommunityID}
	default:
		return o, false
	}
	o.SrcIP, o.DstIP = boundedText(o.SrcIP, 64), boundedText(o.DstIP, 64)
	methodLimit := 32
	if o.Kind == "rpc" {
		methodLimit = 64
	}
	o.Method, o.Path = boundedText(o.Method, methodLimit), boundedText(o.Path, 1024)
	o.Host, o.CommunityID = boundedText(o.Host, 253), boundedText(o.CommunityID, 128)
	o.Qualification = boundedText(o.Qualification, 256)
	return o, true
}

type httpSample struct {
	at     int64
	path   string
	failed bool
}
type httpScan struct {
	samples []httpSample
	last    int64
}
type ApplicationEngine struct {
	lastSweep        int64
	watermark        int64
	observed         bool
	config           Config
	scans            map[string]*httpScan
	beacons          map[string][]int64
	aggregates       *aggregator
	last             map[string]int64
	Alerts, Overflow uint64
	Late             uint64
}

func NewApplication(c Config) *ApplicationEngine {
	return &ApplicationEngine{config: c, scans: map[string]*httpScan{}, beacons: map[string][]int64{}, aggregates: newAggregator(c), last: map[string]int64{}}
}

func (e *ApplicationEngine) Flush() []*types.Alert {
	alerts := e.aggregates.flush()
	e.Alerts += uint64(len(alerts))
	return alerts
}

// Checkpoint emits partial aggregates without advancing capture time or
// resetting scan/beacon history. Delayed older records remain explicit Late.
func (e *ApplicationEngine) Checkpoint() []*types.Alert {
	alerts := e.aggregates.checkpoint("live")
	e.Alerts += uint64(len(alerts))
	return alerts
}

func (e *ApplicationEngine) AggregationStats() (matches, capacity uint64) {
	return e.aggregates.matches, e.aggregates.capacity
}
func globalAddress(s string) bool {
	a, e := netip.ParseAddr(s)
	if e != nil {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range specialUsePrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var specialUsePrefixes = func() []netip.Prefix {
	var result []netip.Prefix
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "100::/64", "2001:db8::/32", "2001:2::/48", "2001:10::/28", "2001:20::/28", "3fff::/20"} {
		result = append(result, netip.MustParsePrefix(p))
	}
	return result
}()

func (e *ApplicationEngine) Observe(o ApplicationObservation) (alerts []*types.Alert) {
	if o.At < 0 || o.Scope.Sensor == "" || o.Scope.Interface == "" || len(o.Scope.Sensor) > 256 || len(o.Scope.Interface) > 256 || len(o.Scope.VLANs) > 4 {
		return nil
	}
	for _, vlan := range o.Scope.VLANs {
		if vlan > 4095 {
			return nil
		}
	}
	src, err := netip.ParseAddr(o.SrcIP)
	if err != nil || src.Zone() != "" {
		return nil
	}
	dst, err := netip.ParseAddr(o.DstIP)
	if err != nil || dst.Zone() != "" {
		return nil
	}
	o.SrcIP, o.DstIP = src.Unmap().String(), dst.Unmap().String()
	methodLimit := 32
	if o.Kind == "rpc" {
		methodLimit = 64
	}
	o.Method, o.Path = boundedText(o.Method, methodLimit), boundedText(o.Path, 1024)
	o.Host, o.CommunityID = boundedText(o.Host, 253), boundedText(o.CommunityID, 128)
	if e.observed && o.At < e.watermark {
		e.Late++
		return nil
	}
	e.watermark = o.At
	alerts = e.aggregates.advance(o.At)
	defer func() { e.Alerts += uint64(len(alerts)) }()
	key := stableKey(o.Scope, o.SrcIP, o.DstIP, o.DstPort)
	if !e.observed || o.At-e.lastSweep >= 1e9 {
		for k, at := range e.last {
			if o.At-at > e.config.BeaconWindowNS {
				delete(e.last, k)
				delete(e.scans, k)
				delete(e.beacons, k)
			}
		}
		e.lastSweep = o.At
	}
	e.observed = true
	for _, s := range e.config.ApprovedSources {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(src) {
			return alerts
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Unmap() == src.Unmap() {
			return alerts
		}
	}
	group := ""
	add := func(name, severity, class string, count, threshold int, first int64, samples []string, limitations ...string) {
		id := stableKey(key, "application", name, group)
		data, _ := json.Marshal(Evidence{Schema: 1, Detector: name, Classification: class, Scope: o.Scope, FirstSeen: first, LastSeen: o.At, Observed: uint64(count), Threshold: uint64(threshold), WindowNS: e.config.WindowNS, Samples: samples, Limitations: limitations})
		alert := &types.Alert{Timestamp: o.At, Name: name, RuleName: name, RecordType: "ApplicationDetection", SrcIP: o.SrcIP, DstIP: o.DstIP, SrcPort: fmt.Sprint(o.SrcPort), DstPort: fmt.Sprint(o.DstPort), Severity: severity, Description: name + ": " + class, CommunityID: o.CommunityID, Tags: []string{"application-detection", class}, MatchedRecord: string(data)}
		alerts = append(alerts, e.aggregates.add(id, alert)...)
	}
	if o.Kind == "ntlm" && globalAddress(o.DstIP) {
		add("policy.public-smb-ntlm", "medium", "policy-observation", 1, 1, o.At, []string{"NTLM identity observed in SMB session setup to a public endpoint"}, "Public addressing does not establish unauthorized authentication or a successful relay")
	}
	if o.Kind == "executable" && o.DstPort != 80 && o.DstPort != 443 {
		add("policy.executable-unusual-port", "low", "policy-observation", 1, 1, o.At, []string{"Executable file magic observed over HTTP"}, "Executable delivery and an unusual service port do not establish execution or maliciousness")
	}
	if o.Kind == "rpc" {
		samples := []string{fmt.Sprintf("interface=%s opnum=%d operation=%s", o.Method, o.Status, o.Path)}
		switch {
		case o.Method == "e3514235-4b06-11d1-ab04-00c04fc2dcd2" && o.Status == 3:
			add("ad.directory-replication", "medium", "policy-observation", 1, 1, o.At, samples, "DRSGetNCChanges is also normal domain-controller replication; unauthorized DCSync is not established")
		case o.Method == "367abb81-9844-35f1-ad32-98f038001003" && (o.Status == 12 || o.Status == 19 || o.Status == 24 || o.Status == 31):
			add("smb.remote-service-control", "medium", "policy-observation", 1, 1, o.At, samples, "Remote service creation/start also occurs in authorized administration; execution success is not inferred")
		case o.Method == "12345678-1234-abcd-ef00-0123456789ab" && o.Status == 65:
			add("ad.printer-notification", "low", "policy-observation", 1, 1, o.At, samples, "Printer notification RPC can be legitimate; coercion and relay success are not inferred")
		case o.Method == "3919286a-b10c-11d0-9ba8-00c04fd92ef5":
			add("ad.domain-role-operation", "low", "policy-observation", 1, 1, o.At, samples, "Domain setup/role operations do not alone establish exploitation")
		}
	}
	if o.Kind == "kerberos" || o.Kind == "rpc" && o.Method == "12345678-1234-abcd-ef00-01234567cffb" && (o.Status == 15 || o.Status == 26) {
		windowKey := stableKey(key, o.Kind, o.Method)
		if len(e.scans) >= e.config.MaxKeys && e.scans[windowKey] == nil {
			e.Overflow++
			return alerts
		}
		w := e.scans[windowKey]
		if w == nil {
			w = &httpScan{}
			e.scans[windowKey] = w
		}
		e.last[windowKey] = o.At
		w.samples = append(w.samples, httpSample{at: o.At, path: o.Path})
		for len(w.samples) > 0 && (o.At-w.samples[0].at > e.config.WindowNS || len(w.samples) > 128) {
			w.samples = w.samples[1:]
		}
		if o.Kind == "kerberos" {
			names := map[string]bool{}
			for _, s := range w.samples {
				names[strings.ToLower(s.path)] = true
			}
			if len(names) >= 10 {
				add("ad.kerberos-user-diversity", "medium", "behavioral-suspicion", len(names), 10, w.samples[0].at, []string{"At least ten distinct user principals requested AS tickets from one source within the detection window"}, "Enumeration, password spraying and authorized multi-user gateways can look alike; password failure is not inferred")
			}
		} else if len(w.samples) >= 32 {
			add("ad.netlogon-authentication-burst", "medium", "behavioral-suspicion", len(w.samples), 32, w.samples[0].at, []string{"Repeated NetrServerAuthenticate2/3 calls for one source and destination service"}, "A Netlogon authentication burst is compatible with Zerologon probing or administrative activity; zero credentials and exploitation success are not established")
		}
	}
	if o.Kind != "http" {
		return alerts
	}
	if !o.DecryptedTLS && (o.DstPort == 443 || o.SrcPort == 443) {
		add("policy.http-on-443", "low", "policy-observation", 1, 1, o.At, []string{"Decoded plaintext HTTP request on TCP/443"}, "Port convention violations can be intentional; malware identity is not inferred")
	}
	if o.Qualification != "" {
		return alerts
	}
	if len(e.scans) >= e.config.MaxKeys && e.scans[key] == nil {
		e.Overflow++
		return alerts
	}
	s := e.scans[key]
	if s == nil {
		s = &httpScan{}
		e.scans[key] = s
	}
	s.last = o.At
	e.last[key] = o.At
	path := o.Path
	if parsed, err := url.ParseRequestURI(path); err == nil {
		path = parsed.Path
	}
	if o.Status >= 100 && o.Qualification == "" {
		s.samples = append(s.samples, httpSample{o.At, path, o.Status >= 400 && o.Status < 500})
	}
	drop := 0
	for drop < len(s.samples) && o.At-s.samples[drop].at > e.config.WindowNS {
		drop++
	}
	copy(s.samples, s.samples[drop:])
	clear(s.samples[len(s.samples)-drop:])
	s.samples = s.samples[:len(s.samples)-drop]
	if len(s.samples) > 128 {
		drop := len(s.samples) - 128
		copy(s.samples, s.samples[drop:])
		clear(s.samples[128:])
		s.samples = s.samples[:128]
	}
	paths := map[string]bool{}
	failures := 0
	for _, p := range s.samples {
		paths[p.path] = true
		if p.failed {
			failures++
		}
	}
	if len(paths) >= 32 && len(s.samples) >= 32 && failures*100 >= len(s.samples)*80 {
		var samples []string
		for p := range paths {
			samples = append(samples, p)
		}
		sort.Strings(samples)
		if len(samples) > 8 {
			samples = samples[:8]
		}
		add("http.scan", "medium", "behavioral-suspicion", len(paths), 32, s.samples[0].at, samples, "High path diversity and at least 80% HTTP 4xx responses; authorization and exploit success are not inferred")
	}
	if e.config.BeaconSamples == 0 || o.RangeTransfer {
		return alerts
	}
	beaconPath := path
	if o.Method == "POST" {
		beaconPath = ""
	} // Encoded C2 paths can vary on every poll.
	beaconKey := stableKey(key, o.Method, strings.ToLower(o.Host), beaconPath)
	if len(e.beacons) >= e.config.MaxKeys && e.beacons[beaconKey] == nil {
		e.Overflow++
		return alerts
	}
	times := e.beacons[beaconKey]
	if len(times) > 0 && o.At <= times[len(times)-1] {
		return alerts
	}
	times = append(times, o.At)
	for len(times) > 0 && o.At-times[0] > e.config.BeaconWindowNS {
		times = times[1:]
	}
	if len(times) > maxBeaconTimes {
		times = times[len(times)-maxBeaconTimes:]
	}
	e.beacons[beaconKey] = times
	e.last[beaconKey] = o.At
	if len(times) >= e.config.BeaconSamples {
		recent := times[len(times)-e.config.BeaconSamples:]
		mean, jitter := BeaconStats(recent)
		cadence := false
		if o.Method == "POST" && jitter > e.config.BeaconJitter {
			if interval, deviation, ok := skippedCadence(recent); ok && interval >= float64(e.config.BeaconMinIntervalNS) && deviation <= e.config.BeaconJitter {
				mean, jitter, cadence = interval, deviation, true
			}
		}
		if mean >= float64(e.config.BeaconMinIntervalNS) && jitter <= e.config.BeaconJitter {
			group = beaconKey
			sample := fmt.Sprintf("HTTP %s %s; interval %.3fs; jitter %.3f", o.Method, path, mean/1e9, jitter)
			if cadence {
				sample = fmt.Sprintf("HTTP POST; cadence %.3fs; maximum phase error %.3f; skipped cycles fitted", mean/1e9, jitter)
			}
			add("c2.beacon", "low", "behavioral-suspicion", len(recent), e.config.BeaconSamples, recent[0], []string{sample}, "Periodic HTTP transactions can be legitimate monitoring or telemetry; C2 intent is not established")
		}
	}
	return alerts
}
