package stream

import (
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func TestIPPHTTPSelection(t *testing.T) {
	matchingEnv(t)
	request := []byte("POST /ipp/print HTTP/1.1\r\nContent-Type: application/ipp\r\nContent-Length: 9\r\n\r\n\x02\x00\x00\x02\x00\x00\x00\x01\x03")
	response := []byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: 9\r\n\r\n\x02\x00\x00\x00\x00\x00\x00\x01\x03")
	for _, port := range []int32{80, 631, 64999} {
		for _, serverOnly := range []bool{false, true} {
			client, server := request, []byte(nil)
			if serverOnly {
				client, server = nil, response
			}
			for split := 1; split <= max(len(client), len(server)); split++ {
				in := &SelectionInput{Transport: core.TCP, ServerPort: port, Conversation: &core.ConversationInfo{},
					PortClient: client[:min(split, len(client))], PortServer: server[:min(split, len(server))],
					ScanBytes: func() ([]byte, []byte) { return client, server }}
				sel, ok := SelectDecoder(in)
				if !ok || sel.Name != "IPP" {
					t.Fatalf("port=%d serverOnly=%t split=%d: %+v", port, serverOnly, split, sel)
				}
			}
		}
	}
	for _, wire := range []string{
		"POST / HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 31\r\n\r\nContent-Type: application/ipp\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 31\r\n\r\nContent-Type: application/ipp\r\n\r\n",
	} {
		sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: 80, PortClient: []byte(wire), ScanClient: []byte(wire), Conversation: &core.ConversationInfo{}})
		if !ok || sel.Name != "HTTP" {
			t.Fatalf("body literal displaced HTTP: %+v", sel)
		}
	}
	config.Instance.ExcludeDecoders = "IPP"
	sel, ok := SelectDecoder(&SelectionInput{Transport: core.TCP, ServerPort: 80, PortClient: request, ScanClient: request, Conversation: &core.ConversationInfo{}})
	if !ok || sel.Name != "HTTP" {
		t.Fatalf("excluded IPP displaced HTTP: %+v", sel)
	}
}
