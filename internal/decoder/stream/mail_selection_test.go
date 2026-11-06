package stream

import (
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"testing"
)

func TestMailSelectionDoesNotGuessFromSharedGreetingOffPort(t *testing.T) {
	matchingEnv(t)
	for _, tc := range []struct {
		port                 int32
		client, server, want string
	}{
		{25, "EHLO fixture.test\r\n", "220 generic mail greeting\r\n", "SMTP"},
		{587, "", "220 generic mail greeting\r\n", "SMTP"},
		{5025, "EHLO fixture.test\r\n", "220 ready\r\n", "SMTP"},
		{21, "USER analyst\r\n", "220 ready\r\n", "FTP"},
		{110, "", "+OK ready\r\n", "POP3"},
		{64999, "", "+OK ready\r\n", ""},
		{64999, "", "220 ready\r\n", ""},
	} {
		c, s := []byte(tc.client), []byte(tc.server)
		sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: tc.port, PortClient: c, PortServer: s, ScanClient: c, ScanServer: s, Conversation: &core.ConversationInfo{}})
		if tc.want == "" {
			if ok {
				t.Fatal("ambiguous off-port greeting guessed", sel)
			}
		} else if !ok || sel.Name != tc.want {
			t.Fatal(tc.port, sel, tc.want)
		}
	}
}
