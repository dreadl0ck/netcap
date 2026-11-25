package evidencelink

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const second = int64(time.Second)

type findingTracks map[string][]types.AuditRecord

func (tracks findingTracks) build(t *testing.T) *FindingContext {
	t.Helper()
	i, err := BuildFindingContext(func(track string, visit func(types.AuditRecord) error) error {
		for _, row := range tracks[track] {
			if err := visit(row); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func findingAlert(record types.AuditRecord) *types.Alert {
	wire, _ := json.Marshal(record)
	return &types.Alert{Timestamp: record.Time(), RecordType: record.NetcapType().String(), MatchedRecord: string(wire), Severity: "high", MatchedRecordSHA256: "original", Examples: []string{`{"kind":"file-match"}`}}
}

func findLinks(t *testing.T, original *types.Alert, index *FindingContext) []RelatedEvidence {
	t.Helper()
	alert := index.Enrich(original)
	if original.Timestamp != alert.Timestamp || original.MatchedRecord != alert.MatchedRecord || original.MatchedRecordSHA256 != alert.MatchedRecordSHA256 || original.Severity != alert.Severity || !slices.Equal(original.Examples, alert.Examples[:len(original.Examples)]) {
		t.Fatal("the context writer changed direct evidence")
	}
	var links []RelatedEvidence
	for _, row := range alert.Examples[len(original.Examples):] {
		var result RelatedEvidence
		if err := json.Unmarshal([]byte(row), &result); err != nil || result.Kind != RelatedEvidenceKind || result.Record.CommunityID == "" {
			t.Fatalf("bad context: %s (%v)", row, err)
		}
		links = append(links, result)
	}
	return links
}

func TestFindingContextLinksOnlyObservedHTTPReferrersInScope(t *testing.T) {
	const client = "192.0.2.1"
	parent := &types.HTTP{Timestamp: 3 * second, SrcIP: client, DstIP: "192.0.2.2", SrcPort: 40001, DstPort: 80, CommunityID: "1:parent", Method: "GET", Host: "landing.example", URL: "/entry?private=query", StatusCode: 200}
	child := &types.HTTP{Timestamp: 10 * second, SrcIP: client, DstIP: "192.0.2.3", SrcPort: 40002, DstPort: 80, CommunityID: "1:child", Method: "GET", Host: "delivery.example", URL: "/file", StatusCode: 200, Referer: "http://LANDING.example:80/entry?private=query"}
	file := &types.File{Timestamp: child.Timestamp, SrcIP: client, DstIP: child.DstIP, SrcPort: child.SrcPort, DstPort: 80, CommunityID: child.CommunityID, Source: "HTTP GET /file (Status: 200)", Host: child.Host, Protocol: "HTTP", FlowDirection: "server_to_client", IsComplete: true}
	for _, tc := range []struct {
		name                        string
		scope, referer              string
		parentTime                  int64
		ambiguous, incomplete, want bool
	}{
		{name: "observed", scope: "vlan-7", parentTime: 3 * second, referer: child.Referer, want: true},
		{name: "other VLAN", scope: "vlan-8", parentTime: 3 * second, referer: child.Referer},
		{name: "future", scope: "vlan-7", parentTime: 13 * second, referer: child.Referer},
		{name: "ambiguous", scope: "vlan-7", parentTime: 3 * second, referer: child.Referer, ambiguous: true},
		{name: "query differs", scope: "vlan-7", parentTime: 3 * second, referer: "http://landing.example/entry?private=other"},
		{name: "incomplete file", scope: "vlan-7", parentTime: 3 * second, referer: child.Referer, incomplete: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, c, f := *parent, *child, *file
			p.Timestamp, c.Referer, f.IsComplete = tc.parentTime, tc.referer, !tc.incomplete
			tracks := findingTracks{
				"Connection": {&types.Connection{TimestampFirst: second, TimestampLast: 20 * second, TransportProto: "TCP", NetworkScope: tc.scope, SrcIP: client, DstIP: p.DstIP, SrcPort: "40001", DstPort: "80", CommunityID: p.CommunityID},
					&types.Connection{TimestampFirst: 8 * second, TimestampLast: 20 * second, TransportProto: "TCP", NetworkScope: "vlan-7", SrcIP: client, DstIP: c.DstIP, SrcPort: "40002", DstPort: "80", CommunityID: c.CommunityID}},
				"HTTP": {&p, &c},
			}
			if tc.ambiguous {
				twice := p
				twice.Timestamp++
				tracks["HTTP"] = append(tracks["HTTP"], &twice)
			}
			links := findLinks(t, findingAlert(&f), tracks.build(t))
			if tc.want {
				if len(links) != 1 || links[0].Relationship != "http-referrer" || links[0].Name != "landing.example" || links[0].Record.Ordinal != 0 || links[0].Via == nil || links[0].Via.Ordinal != 1 {
					t.Fatalf("missing or incorrect HTTP provenance: %+v", links)
				}
			} else if len(links) != 0 {
				t.Fatalf("unqualified file got a referrer: %+v", links)
			}
		})
	}
}

func TestFindingContextDNSAndTLSUseDistinctObservations(t *testing.T) {
	const client, server, resolver = "192.0.2.1", "192.0.2.2", "192.0.2.53"
	for _, variant := range []string{"valid", "ambiguous DNS", "alias expired", "future answer", "reused TLS tuple", "ambiguous handshake"} {
		t.Run(variant, func(t *testing.T) {
			answer := &types.DNS{QR: true, Timestamp: second, TransactionStatus: "answered", CommunityID: "1:dns", SrcIP: resolver, DstIP: client, SrcPort: 53, DstPort: 53001,
				Questions: []*types.DNSQuestion{{Name: "lookup.example.", Type: 1, Class: 1}}, Answers: []*types.DNSResourceRecord{
					{Name: "lookup.example.", CNAMEText: "alias.example", Type: 5, Class: 1, TTL: 11},
					{Name: "alias.example.", IP: server, Type: 1, Class: 1, TTL: 60},
				}}
			tls := &types.Connection{TimestampFirst: 5 * second, TimestampLast: 20 * second, NetworkScope: "vlan-7", TransportProto: "TCP", CommunityID: "1:tls", ObservationID: "one", SrcIP: client, DstIP: server, SrcPort: "40001", DstPort: "443"}
			hello := &types.TLSClientHello{Timestamp: 6 * second, SNI: "sni.example", CommunityID: tls.CommunityID, SrcIP: client, DstIP: server, SrcPort: 40001, DstPort: 443}
			leaf := &types.TLSCertificate{Timestamp: 8 * second, CertificateSender: "server", CommunityID: tls.CommunityID, SrcIP: server, DstIP: client, SrcPort: 443, DstPort: 40001}
			tracks := findingTracks{
				"Connection": {tls, &types.Connection{TimestampFirst: second / 2, TimestampLast: 15 * second, NetworkScope: "vlan-7", TransportProto: "UDP", SrcIP: client, DstIP: resolver, SrcPort: "53001", DstPort: "53", CommunityID: answer.CommunityID}},
				"DNS":        {answer}, "TLSClientHello": {hello},
			}
			wantDNS, wantTLS := true, true
			switch variant {
			case "ambiguous DNS":
				secondAnswer := *answer
				secondAnswer.Questions = []*types.DNSQuestion{{Name: "other.example", Type: 1, Class: 1}}
				secondAnswer.Answers = []*types.DNSResourceRecord{{Name: "other.example", Type: 1, Class: 1, IP: server, TTL: 60}}
				tracks["DNS"] = append(tracks["DNS"], &secondAnswer)
				wantDNS = false
			case "alias expired":
				answer.Answers[0].TTL = 4
				wantDNS = false
			case "future answer":
				answer.Timestamp = 7 * second
				wantDNS = false
			case "reused TLS tuple":
				reused := *tls
				reused.TimestampFirst, reused.ObservationID = 7*second, "two"
				tls.TimestampLast = 6 * second
				tracks["Connection"] = append(tracks["Connection"], &reused)
				wantTLS = false
			case "ambiguous handshake":
				other := *hello
				other.Timestamp++
				tracks["TLSClientHello"] = append(tracks["TLSClientHello"], &other)
				wantTLS = false
			}
			seen := map[string]bool{}
			for _, l := range findLinks(t, findingAlert(leaf), tracks.build(t)) {
				seen[l.Relationship] = true
				if l.IP != server || !strings.HasSuffix(l.Name, ".example") || l.Record.Timestamp >= leaf.Timestamp {
					t.Fatalf("bad origin record: %+v", l)
				}
			}
			if seen["dns-resolution"] != wantDNS || seen["tls-server-name"] != wantTLS {
				t.Fatalf("unexpected links: %v", seen)
			}
		})
	}
}
