package behavior

import (
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestLateralRecordTransportAndAuthenticationLimits(t *testing.T) {
	at := time.Unix(1700000000, 0).UnixNano()
	fact := Fact{Kind: "service", Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Port: 445, Token: "43210:123", Scope: Scope{Sensor: "sensor", Interface: "eth0", VLANs: []uint16{42}}}
	evidence := Evidence{Detector: "lateral.smb-fanout", Observed: fact, WindowNS: int64(time.Minute)}
	connection := &types.Connection{TimestampFirst: at - int64(time.Second), TimestampLast: at + int64(10*time.Minute), TransportProto: "TCP", SrcIP: fact.SrcIP, DstIP: fact.DstIP, SrcPort: "43210", DstPort: "445", NumRSTFlags: 1}
	context := MatchLateralRecord(evidence, at, connection, 7)
	if context == nil || context.Outcome != "TCP reset observed" || context.Authentication != "unavailable" || context.ScopeAvailable || context.CaptureLagNS != int64(10*time.Minute) || context.Index != 7 || len(context.SHA256) != 64 {
		t.Fatalf("late connection: %+v", context)
	}
	connection.SrcPort = "43211"
	if MatchLateralRecord(evidence, at, connection, 0) != nil {
		t.Fatal("different flow source port matched")
	}
	connection.SrcPort = "43210"
	connection.TimestampFirst = at + 1
	if MatchLateralRecord(evidence, at, connection, 0) != nil {
		t.Fatal("post-alert connection attributed as contributing evidence")
	}
	smb := &types.SMB{Timestamp: at + int64(time.Second), SrcIP: fact.DstIP, DstIP: fact.SrcIP, SrcPort: 445, DstPort: 43210, IsResponse: true, Status: 0xc000006d, AuthStatus: "FAILED"}
	context = MatchLateralRecord(evidence, at, smb, 8)
	if context == nil || context.Authentication != "FAILED" || context.Status != 0xc000006d || !context.Response || context.ScopeAvailable {
		t.Fatalf("SMB response: %+v", context)
	}
	smb.AuthStatus = ""
	if context = MatchLateralRecord(evidence, at, smb, 8); context.Authentication != "unavailable" {
		t.Fatal("NT status alone claimed authentication failure")
	}
	smb.AuthStatus, smb.IsEncrypted = "FAILED", true
	if context = MatchLateralRecord(evidence, at, smb, 8); context.Authentication != "unavailable" {
		t.Fatal("encrypted SMB claimed readable authentication")
	}
	smb.Timestamp = at + int64(2*time.Minute)
	if MatchLateralRecord(evidence, at, smb, 8) != nil {
		t.Fatal("unbounded SMB time match")
	}
}
func TestLateralRecordMatcherUsesRelatedSourcePortConstraints(t *testing.T) {
	fact := Fact{Kind: "service", Protocol: "tcp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Port: 445, Token: ":9"}
	e := Evidence{Detector: "lateral.smb-fanout", Related: []Fact{fact}, WindowNS: int64(time.Minute)}
	r := &types.Connection{TransportProto: "TCP", SrcIP: fact.SrcIP, DstIP: fact.DstIP, SrcPort: "5678", DstPort: "445", TimestampFirst: 1, TimestampLast: 1}
	if NewLateralRecordMatcher(e, 1).Match(r, 0) != nil {
		t.Fatal("an empty token prefix must not match an arbitrary source port")
	}
	e.Related[0].Token = ""
	if got := NewLateralRecordMatcher(e, 1).Match(r, 7); got == nil || got.ScopeAvailable || got.Index != 7 {
		t.Fatalf("tuple-only candidate: %+v", got)
	}
}

func BenchmarkLateralRecordNonmatch(b *testing.B) {
	e := Evidence{Detector: "lateral.smb-fanout", WindowNS: int64(time.Minute), Related: make([]Fact, 256)}
	for i := range e.Related {
		e.Related[i] = Fact{Kind: "service", Protocol: "tcp", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Port: 445, Token: "1234:9"}
	}
	r := &types.Connection{TransportProto: "TCP", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "5678", DstPort: "445", TimestampFirst: 1, TimestampLast: 1}
	m := NewLateralRecordMatcher(e, 1)
	b.ReportAllocs()
	for b.Loop() {
		if m.Match(r, 0) != nil {
			b.Fatal("unexpected match")
		}
	}
}
