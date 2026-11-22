package rules

import (
	"testing"

	"github.com/dreadl0ck/netcap/types"
)

// NetSupport RAT clients poll a gateway with cleartext HTTP, often on TCP/443.
// The client announces itself in User-Agent; the gateway only in its Server header.
func TestNetSupportRulesMatchTheHeaderEachSideSends(t *testing.T) {
	rules := exampleRules(t, "suspicious_user_agents.yml")
	poll := &types.HTTP{
		Method:     "POST",
		URL:        "http://192.0.2.10/fakeurl.htm",
		UserAgent:  "NetSupport Manager/1.3",
		ServerName: "NetSupport Gateway/1.92 (Windows NT)",
		StatusCode: 200,
	}
	for _, c := range []struct {
		rule   string
		record *types.HTTP
		want   bool
	}{
		{"NetSupport Manager RAT User Agent Detected", poll, true},
		{"NetSupport Gateway Server Header Detected", poll, true},
		{"NetSupport Gateway Server Header Detected", &types.HTTP{UserAgent: "NetSupport Manager/1.3"}, false},
		{"NetSupport Gateway Server Header Detected", &types.HTTP{ServerName: "Apache/2.4.58 (Ubuntu)"}, false},
	} {
		if got := matches(t, rules[c.rule], c.record); got != c.want {
			t.Errorf("%s on %+v = %v, want %v", c.rule, c.record, got, c.want)
		}
	}
}
