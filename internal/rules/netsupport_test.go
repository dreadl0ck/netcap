package rules

import (
	"slices"
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

func TestNetSupportFallbackKeepsIndependentlySelectedHTTPRules(t *testing.T) {
	post := exampleRules(t, "malware.yml")["HTTP POST to IP"]
	proxy := exampleRules(t, "suspicious_traffic.yml")["Unknown HTTP Proxy Detection"]
	client := exampleRules(t, "suspicious_user_agents.yml")[netSupportClientRule]
	poll := &types.HTTP{Timestamp: 1e9, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Host: "192.0.2.2", Method: "POST", URL: "http://192.0.2.2/check", UserAgent: "NetSupport Manager/1.3"}
	for _, tc := range []struct {
		name   string
		modify func(*Rule)
		custom bool
		want   []string
	}{
		{name: "generic rules only", want: []string{post.Name, proxy.Name}},
		{name: "specific disabled", modify: func(r *Rule) { r.Enabled = false }, want: []string{post.Name, proxy.Name}},
		{name: "specific predicate did not match", modify: func(r *Rule) { r.Expression = `UserAgent == "NetSupport Manager/2"` }, want: []string{post.Name, proxy.Name}},
		{name: "specific threshold not reached", modify: func(r *Rule) { r.Threshold, r.DedupeBy = 2, nil }, want: []string{post.Name, proxy.Name}},
		{name: "custom generic same name", custom: true, modify: func(*Rule) {}, want: []string{post.Name, client.Name}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generic := post.SavedCopy()
			if tc.custom {
				generic.Expression = `Method == "POST"`
			}
			selected := []*Rule{&generic, proxy}
			if tc.modify != nil {
				specific := client.SavedCopy()
				tc.modify(&specific)
				selected = append(selected, &specific)
			}
			writer := new(MockAlertWriter)
			replay, err := NewAuditReplay(&Config{Rules: selected}, writer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := replay.Evaluate(poll); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, alert := range writer.alerts {
				names = append(names, alert.RuleName)
			}
			if !slices.Equal(names, tc.want) {
				t.Fatalf("findings = %v, want %v", names, tc.want)
			}
		})
	}
}

func TestNetSupportPollingKeepsSpecificFindingsAcrossWindows(t *testing.T) {
	names := []string{"HTTP POST to IP", "Unknown HTTP Proxy Detection", "NetSupport Manager RAT User Agent Detected", "NetSupport Gateway Server Header Detected"}
	available := exampleRules(t, "suspicious_user_agents.yml")
	available[names[0]] = exampleRules(t, "malware.yml")[names[0]]
	available[names[1]] = exampleRules(t, "suspicious_traffic.yml")[names[1]]
	config := &Config{}
	for _, name := range names {
		config.Rules = append(config.Rules, available[name])
	}
	writer := new(MockAlertWriter)
	replay, err := NewAuditReplay(config, writer)
	if err != nil {
		t.Fatal(err)
	}
	poll := types.HTTP{Timestamp: 1e9, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", Host: "192.0.2.2", Method: "POST", URL: "http://192.0.2.2/check", UserAgent: "NetSupport Manager/1.3", ServerName: "NetSupport Gateway/1.92"}
	for _, r := range []*types.HTTP{&poll, {Timestamp: 3601e9, SrcIP: poll.SrcIP, DstIP: poll.DstIP, Host: poll.Host, Method: poll.Method, URL: poll.URL, UserAgent: poll.UserAgent, ServerName: poll.ServerName}} {
		if _, err := replay.Evaluate(r); err != nil {
			t.Fatal(err)
		}
	}
	if len(writer.alerts) != 2 || writer.alerts[0].RuleName != names[2] || writer.alerts[1].RuleName != names[3] {
		t.Fatalf("polling produced extra or generic findings: %+v", writer.alerts)
	}
	poll.Timestamp, poll.UserAgent, poll.ServerName = 7201e9, "generic", "generic"
	if n, err := replay.Evaluate(&poll); err != nil || n != 2 {
		t.Fatalf("generic proxy and IP POST evidence was lost: %d (%v)", n, err)
	}
	poll.Timestamp, poll.Method, poll.UserAgent = 10801e9, "CONNECT", "NetSupport Manager/1.3"
	if n, err := replay.Evaluate(&poll); err != nil || n != 1 || writer.alerts[len(writer.alerts)-1].RuleName != names[1] {
		t.Fatalf("observed CONNECT was lost: %d (%v)", n, err)
	}
}
