package torobserve

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestTorObservationIsBoundToScopeAndTCPGeneration(t *testing.T) {
	cert := &types.TLSCertificate{Timestamp: 50, CertificateSender: "server", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 9444, DstPort: 5000,
		SubjectCommonName: "www.abcdefgh23.com", IssuerCommonName: "www.abcdefgh24.net", SHA256Fingerprint: "fixture"}
	var index Index
	index.Observe("first", cert)
	conn := &types.Connection{NetworkScope: "first", TransportProto: "TCP", SrcIP: "192.0.2.2", DstIP: "192.0.2.1", SrcPort: "5000", DstPort: "9444", TimestampFirst: 40, TimestampLast: 60}
	if got := index.Match(conn); got != "fixture" {
		t.Fatalf("certificate failed to match its own flow: %q", got)
	}
	conn.NetworkScope = "second"
	if got := index.Match(conn); got != "" {
		t.Fatalf("cross-scope attribution: %q", got)
	}
	conn.NetworkScope, conn.TimestampFirst, conn.TimestampLast = "first", 70, 90
	if got := index.Match(conn); got != "" {
		t.Fatalf("reused tuple inherited prior TLS observation: %q", got)
	}
	cert.SubjectAltNames = []string{"fixture.test"}
	if Candidate(cert) {
		t.Fatal("ordinary SAN-bearing certificate matched")
	}
}
