package stream

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"testing"
)

func TestW70SyslogAndCIPTransportSelection(t *testing.T) {
	matchingEnv(t)
	for _, tc := range []struct {
		name      string
		transport core.TransportProtocol
		port      int32
		data      []byte
		want      string
	}{
		{"tcp-syslog-counted", core.TCP, 514, []byte("12 <13>message"), "Syslog"},
		{"tcp-syslog-lines", core.TCP, 514, []byte("<13>message\n"), "Syslog"},
		{"udp-syslog", core.UDP, 514, []byte("<13>message"), "Syslog"},
		{"udp-cip", core.UDP, 44818, matchingSample(t, "CIP").client, "CIP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, ok := SelectDecoder(&SelectionInput{Transport: tc.transport, ServerPort: tc.port, PortClient: tc.data, ScanClient: tc.data, Conversation: &core.ConversationInfo{}})
			if !ok || sel.Name != tc.want {
				t.Fatalf("selected %q (%v), want %q", sel.Name, ok, tc.want)
			}
		})
	}
}
