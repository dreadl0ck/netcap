package rules

import (
	"errors"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

func TestUnimplementedFirewallActionsNeverReportSuccess(t *testing.T) {
	configuration := reloadConfig("DstPort == 443", 1)
	configuration.Rules[0].Actions = []*ResponseAction{{Type: "iptables_rate_limit"}, {Type: "iptables_log"}}
	engine, err := NewEngineFromConfig(configuration, alertWriterFunc(func(*types.Alert) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	record := &types.TCP{Timestamp: time.Now().UnixNano(), SrcIP: "192.0.2.1", DstIP: "198.51.100.1", DstPort: 443}
	if count, err := engine.Evaluate(record); err != nil || count != 1 {
		t.Fatalf("alert generation changed: %d %v", count, err)
	}
	stats := engine.GetActionStats()
	if stats["actions_executed"] != 2 || stats["actions_failed"] != 2 || stats["actions_success"] != 0 || stats["ips_blocked"] != 0 {
		t.Fatal(stats)
	}
	for _, action := range configuration.Rules[0].Actions {
		if err := engine.executeResponseAction(action, record, &types.Alert{}); !errors.Is(err, ErrUnsupportedResponseAction) {
			t.Fatalf("unsupported action %s returned %v", action.Type, err)
		}
	}
}
