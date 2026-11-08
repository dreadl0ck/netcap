package types

import (
	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/gogo/protobuf/proto"
	"testing"
)

func TestAuditSemanticsCSVAndLegacyWire(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	records := []AuditRecord{&HTTP{CommunityID: "1:owned"}, &DNS{CommunityID: "1:owned"}, &Kerberos{CommunityID: "1:owned"}, &TACACS{CommunityID: "1:owned"}, &IPP{CommunityID: "1:owned"}, &Zabbix{CommunityID: "1:owned"}, &Protobuf{CommunityID: "1:owned"}, &OPCUA{CommunityID: "1:owned"}, &S7Comm{CommunityID: "1:owned"}, &PROFINET{CommunityID: "1:owned"}, &TLSCertificate{CommunityID: "1:owned", AssessmentBasis: "capture-time", ValidityState: "valid"}, &RDP{CommunityID: "1:owned", NegotiationOutcome: "accepted", AuthenticationOutcome: "unknown"}}
	for _, r := range records {
		t.Run(r.NetcapType().String(), func(t *testing.T) {
			h, row := r.CSVHeader(), r.CSVRecord()
			if len(h) != len(row) || len(r.Encode()) != len(h) {
				t.Fatal("CSV/header length mismatch")
			}
			found := false
			for i, name := range h {
				if name == "CommunityID" {
					found = row[i] == "1:owned"
				}
			}
			if !found {
				t.Fatal("CSV omitted CommunityID")
			}
			r.Inc() // Metrics label inventories must evolve with appended CSV columns.
			p := r.(proto.Message)
			if err := proto.Unmarshal([]byte{8, 1}, p); err != nil {
				t.Fatal("historical timestamp-only record rejected", err)
			}
			if r.Time() != 1 {
				t.Fatal("historical timestamp moved")
			}
		})
	}
}
