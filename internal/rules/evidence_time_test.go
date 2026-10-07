package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestRuleAlertPreservesObservationTimeAndProvenance(t *testing.T) {
	rule := &Rule{Name: "fixture", Type: "TCP", Expression: "DstPort == 443", Severity: "low", Enabled: true}
	if err := CompileRules(&Config{Rules: []*Rule{rule}}); err != nil {
		t.Fatal(err)
	}
	record := &types.TCP{Timestamp: 1700000000000000001, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 12345, DstPort: 443}
	before := time.Now().UnixNano()
	alert, err := EvaluateRule(rule, record)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UnixNano()
	if alert.Timestamp != record.Timestamp || alert.TimestampBasis != "record-time" || alert.DetectedAt < before || alert.DetectedAt > after || len(alert.RuleDigest) != 64 {
		t.Fatalf("observation conflated with processing time: %s", alert)
	}
	hash := sha256.Sum256([]byte(alert.MatchedRecord))
	if alert.MatchedRecordSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("matched-record digest does not identify attached evidence")
	}
	again, err := EvaluateRule(rule, record)
	if err != nil {
		t.Fatal(err)
	}
	if again.RuleDigest != alert.RuleDigest || again.MatchedRecordSHA256 != alert.MatchedRecordSHA256 {
		t.Fatal("replay changed rule/evidence provenance")
	}
	rule.Severity = "high"
	changed, err := EvaluateRule(rule, record)
	if err != nil {
		t.Fatal(err)
	}
	if changed.RuleDigest == alert.RuleDigest {
		t.Fatal("effective rule change not reflected in digest")
	}
}
