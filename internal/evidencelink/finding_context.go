package evidencelink

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const (
	RelatedEvidenceKind = "related-evidence"
	maxContextRecords   = 250_000
	maxContextBytes     = 32 << 20
	maxContextPerKey    = 128
	maxContextPerAlert  = 5
)

var errFindingContextLimit = errors.New("finding context scan limit reached")

// RelatedEvidence refers to an observed record in another audit track. Its
// fields describe the relationship, not an assertion that the peer is malicious.
type RelatedEvidence struct {
	Kind         string      `json:"kind"`
	Relationship string      `json:"relationship"`
	Name         string      `json:"name,omitempty"`
	IP           string      `json:"ip,omitempty"`
	Record       ContextRef  `json:"record"`
	Via          *ContextRef `json:"via,omitempty"`
}

type ContextRef struct {
	Type        string `json:"type"`
	Ordinal     int    `json:"ordinal"`
	Timestamp   int64  `json:"timestampNs,string"`
	CommunityID string `json:"communityId"`
}

type findingFlow struct {
	cid  string
	a, b netip.AddrPort
}

func contextAddress(ip string) netip.Addr {
	if len(ip) > 128 {
		return netip.Addr{}
	}
	a, _ := netip.ParseAddr(ip)
	if a.Zone() != "" {
		return netip.Addr{}
	}
	return a.Unmap()
}

func contextFlow(cid, src, dst string, sp, dp int32) (findingFlow, netip.Addr, netip.Addr) {
	a, b := contextAddress(src), contextAddress(dst)
	if !Joinable(cid) || len(cid) > 128 || !a.IsValid() || !b.IsValid() || sp < 1 || sp > 65535 || dp < 1 || dp > 65535 {
		return findingFlow{}, netip.Addr{}, netip.Addr{}
	}
	left, right := netip.AddrPortFrom(a, uint16(sp)), netip.AddrPortFrom(b, uint16(dp))
	if left.Compare(right) > 0 {
		left, right = right, left
	}
	return findingFlow{cid, left, right}, a, b
}

type findingConnection struct {
	scope, observation, protocol string
	first, last                  int64
}

type findingHello struct {
	ref    ContextRef
	name   string
	client netip.AddrPort
}

// FindingContext contains only bounded projections of finalized audit records.
type FindingContext struct {
	connections map[findingFlow][]findingConnection
	http        map[findingFlow][]findingHTTP
	urls        map[findingURLKey][]findingHTTP
	dns         map[findingDNSKey][]findingAnswer
	hellos      map[findingFlow][]findingHello
	bytes       int
	limited     bool
}

// BuildFindingContext reads the required tracks through a confined scanner. The
// scanner must deliver every row in wire order, or report an error. A scan that
// exhausts its budget cannot establish uniqueness, so its context is withheld.
func BuildFindingContext(scan func(string, func(types.AuditRecord) error) error) (*FindingContext, error) {
	i := &FindingContext{
		connections: make(map[findingFlow][]findingConnection),
		http:        make(map[findingFlow][]findingHTTP), urls: make(map[findingURLKey][]findingHTTP),
		dns: make(map[findingDNSKey][]findingAnswer), hellos: make(map[findingFlow][]findingHello),
	}
	for _, typ := range []string{"Connection", "DNS", "HTTP", "TLSClientHello"} {
		ordinal := 0
		err := scan(typ, func(record types.AuditRecord) error {
			if ordinal >= maxContextRecords || i.bytes >= maxContextBytes {
				return errFindingContextLimit
			}
			i.add(typ, ordinal, record)
			ordinal++
			return nil
		})
		if errors.Is(err, errFindingContextLimit) || i.bytes >= maxContextBytes {
			return &FindingContext{limited: true}, nil
		}
		if err != nil {
			return nil, err
		}
		if typ == "Connection" && len(i.connections) == 0 {
			break
		}
	}
	return i, nil
}

// A hot key is unusable once its capped history cannot establish uniqueness.
func addContext[K comparable, V any](index map[K][]V, k K, v V) {
	if rows, ok := index[k]; !ok || (rows != nil && len(rows) < maxContextPerKey) {
		index[k] = append(rows, v)
	} else {
		index[k] = nil
	}
}

func (i *FindingContext) add(typ string, ordinal int, record types.AuditRecord) {
	ref := ContextRef{Type: typ, Ordinal: ordinal, Timestamp: record.Time()}
	switch r := record.(type) {
	case *types.Connection:
		i.addFindingConnection(r)
	case *types.HTTP:
		ref.CommunityID = r.CommunityID
		i.addFindingHTTP(r, ref)
	case *types.DNS:
		ref.CommunityID = r.CommunityID
		i.addFindingDNS(r, ref)
	case *types.TLSClientHello:
		ref.CommunityID = r.CommunityID
		key, src, _ := contextFlow(r.CommunityID, r.SrcIP, r.DstIP, r.SrcPort, r.DstPort)
		name := contextName(r.SNI)
		if r.Timestamp > 0 && name != "" && r.ReassemblyStatus == "" && (r.HelloFormat == "" || r.HelloFormat == "TLS") && i.connectionAt(key, r.Timestamp, "TCP") != nil {
			addContext(i.hellos, key, findingHello{ref, name, netip.AddrPortFrom(src, uint16(r.SrcPort))})
			i.bytes += 512 + len(name)
		}
	}
}

func (i *FindingContext) addFindingConnection(r *types.Connection) {
	sp, errSP := strconv.ParseUint(r.SrcPort, 10, 16)
	dp, errDP := strconv.ParseUint(r.DstPort, 10, 16)
	key, _, _ := contextFlow(r.CommunityID, r.SrcIP, r.DstIP, int32(sp), int32(dp))
	if errSP != nil || errDP != nil || key.cid == "" || len(r.NetworkScope) > 512 || len(r.ObservationID) > 128 ||
		(r.TransportProto != "TCP" && r.TransportProto != "UDP") || r.TimestampFirst < 0 || r.TimestampLast < r.TimestampFirst {
		return
	}
	for n, old := range i.connections[key] {
		if r.ObservationID != "" && old.observation == r.ObservationID && old.scope == r.NetworkScope && old.protocol == r.TransportProto {
			i.connections[key][n].first = min(old.first, r.TimestampFirst)
			i.connections[key][n].last = max(old.last, r.TimestampLast)
			return
		}
	}
	addContext(i.connections, key, findingConnection{r.NetworkScope, r.ObservationID, r.TransportProto, r.TimestampFirst, r.TimestampLast})
	i.bytes += 512 + len(r.NetworkScope) + len(r.ObservationID)
}

func (i *FindingContext) connectionAt(key findingFlow, at int64, protocol string) *findingConnection {
	var match *findingConnection
	rows := i.connections[key]
	for n := range rows {
		c := &rows[n]
		if c.protocol != protocol || at < c.first || at > c.last {
			continue
		}
		if match != nil || c.scope == "" {
			return nil
		}
		match = c
	}
	return match
}

func contextName(raw string) string {
	name := strings.TrimSuffix(raw, ".")
	if len(name) == 0 || len(name) > 253 {
		return ""
	}
	name = strings.ToLower(name)
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return ""
			}
		}
	}
	return name
}

// Enrich appends links to an existing finding without changing its matched
// record, identity, severity, counts or evidence range.
func (i *FindingContext) Enrich(alert *types.Alert) *types.Alert {
	if alert == nil || alert.Timestamp <= 0 || len(alert.MatchedRecord) > types.MaxMatchedRecordBytes ||
		slices.Contains(alert.Tags, "kind:inventory") || (strings.EqualFold(alert.Severity, "info") && !slices.Contains(alert.Tags, "kind:finding")) {
		return alert
	}
	var links []RelatedEvidence
	switch alert.RecordType {
	case "NC_File":
		var f types.File
		if json.Unmarshal([]byte(alert.MatchedRecord), &f) == nil {
			links = i.forFile(&f)
		}
	case "NC_HTTP":
		var h types.HTTP
		if json.Unmarshal([]byte(alert.MatchedRecord), &h) == nil {
			links = i.forHTTP(&h)
		}
	case "NC_TLSClientHello":
		var h types.TLSClientHello
		if json.Unmarshal([]byte(alert.MatchedRecord), &h) == nil && h.ReassemblyStatus == "" {
			key, client, server := contextFlow(h.CommunityID, h.SrcIP, h.DstIP, h.SrcPort, h.DstPort)
			links = i.addDNSLink(nil, key, h.Timestamp, client, server, h.SNI)
		}
	case "NC_TLSCertificate":
		var leaf types.TLSCertificate
		if json.Unmarshal([]byte(alert.MatchedRecord), &leaf) == nil {
			links = i.forCertificate(&leaf)
		}
	case "NC_Connection":
		var c types.Connection
		if json.Unmarshal([]byte(alert.MatchedRecord), &c) == nil && c.TransportProto == "TCP" {
			sp, e1 := strconv.ParseUint(c.SrcPort, 10, 16)
			dp, e2 := strconv.ParseUint(c.DstPort, 10, 16)
			if e1 == nil && e2 == nil {
				key, client, server := contextFlow(c.CommunityID, c.SrcIP, c.DstIP, int32(sp), int32(dp))
				links = i.addDNSLink(nil, key, c.TimestampFirst, client, server, c.Sni)
			}
		}
	default:
		return alert
	}
	if len(links) == 0 && !i.limited {
		return alert
	}
	result := *alert
	result.Examples = slices.Clone(alert.Examples)
	if i.limited {
		result.Examples = append(result.Examples, `{"kind":"related-evidence-limit","reason":"index-budget"}`)
	}
	for _, link := range links[:min(len(links), maxContextPerAlert)] {
		link.Kind = RelatedEvidenceKind
		data, _ := json.Marshal(link)
		result.Examples = append(result.Examples, string(data))
	}
	return &result
}

func (i *FindingContext) forCertificate(cert *types.TLSCertificate) []RelatedEvidence {
	if cert.ChainIndex != 0 || cert.CertificateSender != "server" || cert.TCPObservation != "" {
		return nil
	}
	key, client, server := contextFlow(cert.CommunityID, cert.DstIP, cert.SrcIP, cert.DstPort, cert.SrcPort)
	conn := i.connectionAt(key, cert.Timestamp, "TCP")
	if conn == nil {
		return nil
	}
	var hello *findingHello
	rows := i.hellos[key]
	for n := range rows {
		h := &rows[n]
		if h.client != netip.AddrPortFrom(client, uint16(cert.DstPort)) || h.ref.Timestamp >= cert.Timestamp || cert.Timestamp-h.ref.Timestamp > int64(10*time.Second) || i.connectionAt(key, h.ref.Timestamp, "TCP") != conn {
			continue
		}
		if hello != nil {
			hello = nil
			break
		}
		hello = h
	}
	var links []RelatedEvidence
	var name string
	if hello != nil {
		name = hello.name
		links = append(links, RelatedEvidence{Relationship: "tls-server-name", Name: name, IP: server.String(), Record: hello.ref})
	}
	return i.addDNSLink(links, key, cert.Timestamp, client, server, name)
}
