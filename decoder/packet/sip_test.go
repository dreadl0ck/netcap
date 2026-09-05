package packet

import (
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

func TestSIPRequestURI(t *testing.T) {
	previous := conf
	conf = &config.Config{}
	t.Cleanup(func() { conf = previous })
	for _, tt := range []struct {
		name, start, header, want string
	}{
		{"request", "INVITE sip:alice@example.com SIP/2.0", "", "sip:alice@example.com"},
		{"misleading header", "OPTIONS sips:bob@example.com:5061 SIP/2.0", "Request-URI: sip:wrong@example.com\r\n", "sips:bob@example.com:5061"},
		{"response", "SIP/2.0 200 OK", "Request-URI: sip:wrong@example.com\r\n", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sip := layers.SIP{Headers: make(map[string][]string)}
			data := []byte(tt.start + "\r\n" + tt.header + "CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
			if err := sip.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				t.Fatal(err)
			}
			record := sipDecoder.Handler(&sip, 123).(*types.SIP)
			if record.RequestURI != tt.want || record.Timestamp != 123 {
				t.Fatalf("got URI %q timestamp %d, want %q timestamp 123", record.RequestURI, record.Timestamp, tt.want)
			}
		})
	}
}
