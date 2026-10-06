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
