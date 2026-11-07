package webui

import (
	"encoding/json"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"net/http/httptest"
	"testing"
)

func TestCertificateAssessmentAPIAndLegacyUnknown(t *testing.T) {
	dir := t.TempDir()
	const timestamp = int64(1590969600000000123)
	writeTimelineAuditFile(t, dir, "TLSCertificate", types.Type_NC_TLSCertificate, []proto.Message{
		&types.TLSCertificate{Timestamp: timestamp, SHA256Fingerprint: "owned", AssessmentTime: timestamp, AssessmentBasis: "capture-time", ValidityState: "valid", SelfSignatureState: "verified", CertificateSender: "client", SrcIP: "192.0.2.1", CommunityID: "1:owned"},
		&types.TLSCertificate{Timestamp: timestamp + 100, SHA256Fingerprint: "owned", AssessmentTime: timestamp + 100, AssessmentBasis: "capture-time", ValidityState: "valid", SelfSignatureState: "verified", CertificateSender: "server", SrcIP: "192.0.2.2", CommunityID: "1:owned"},
		&types.TLSCertificate{Timestamp: timestamp, SHA256Fingerprint: "legacy", IsExpired: false, IsSelfSigned: false},
	})
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleCertificates(w, httptest.NewRequest("GET", "/api/certificates", nil))
	if w.Code != 200 {
		t.Fatalf("certificate API: %d %s", w.Code, w.Body.String())
	}
	var response CertificatesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.TotalCount != 3 {
		t.Fatal("client/server or assessment merged", response.TotalCount)
	}
	for _, row := range response.Certificates {
		if row.SHA256Fingerprint == "legacy" {
			if row.ValidityState != "legacy-unqualified" || row.AssessmentBasis != "legacy-unqualified" || row.CertificateSender != "unknown" {
				t.Fatalf("legacy false flags became validity: %+v", row)
			}
		} else {
			if row.AssessmentTime != "1590969600000000123" && row.AssessmentTime != "1590969600000000223" {
				t.Fatal("nanoseconds lost", row.AssessmentTime)
			}
			if row.CertificateSender == "client" && row.SrcIP != "192.0.2.1" || row.CertificateSender == "server" && row.SrcIP != "192.0.2.2" {
				t.Fatal("mutual TLS sender lost")
			}
		}
	}
}
