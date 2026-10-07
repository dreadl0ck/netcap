package webui

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

func TestAlertEvidenceTimeAndIdentity(t *testing.T) {
	a := &types.Alert{Timestamp: 1700000000000000001, DetectedAt: 1800000000000000001, TimestampBasis: "record-time", RuleName: "fixture", RuleDigest: "rule-digest", MatchedRecordSHA256: "record-digest", SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
	first := alertResponse(a)
	if first.Timestamp != 1700000000000 || first.TimestampNs != "1700000000000000001" || first.DetectedAtNs != "1800000000000000001" || first.RuleDigest != a.RuleDigest {
		t.Fatalf("lost evidence time precision: %+v", first)
	}
	a.DetectedAt++
	if first.AlertID == alertResponse(a).AlertID {
		t.Fatal("separate evaluations share a resolution ID")
	}
	a.Timestamp++
	second := alertResponse(a)
	if second.Timestamp != first.Timestamp || second.TimestampNs == first.TimestampNs || second.AlertID == first.AlertID {
		t.Fatal("nanosecond observations collapsed into one millisecond alert")
	}
	legacy := AlertResponse{RuleName: "fixture", Timestamp: 1, SrcIP: "192.0.2.1", DstIP: "192.0.2.2"}
	if generateAlertID(legacy) != "fixture-1-192.0.2.1-192.0.2.2" {
		t.Fatal("legacy resolution identity changed")
	}
}
