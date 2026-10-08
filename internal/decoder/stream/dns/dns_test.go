package dns

import (
	"encoding/binary"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"testing"
	"time"
)

func framed(t *testing.T, response bool) []byte {
	t.Helper()
	wire := &layers.DNS{ID: 7, QR: response, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, wire); err != nil {
		t.Fatal(err)
	}
	payload := buffer.Bytes()
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(payload)))
	return append(prefix, payload...)
}

func fragment(data []byte, at int64, server bool) *core.StreamData {
	f := &core.StreamData{RawData: data, CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(0, at)}}
	if server {
		f.Dir = reassembly.TCPDirServerToClient
	}
	return f
}

func TestTCPDNSFramingAndPairingAtEveryBoundary(t *testing.T) {
	query, response := framed(t, false), framed(t, true)
	for split := 0; split <= len(query); split++ {
		conversation := &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 53, CommunityID: "1:test"}
		conversation.Data = core.DataFragments{fragment(query[:split], 100, false), fragment(query[split:], 200, false), fragment(response, 500, true)}
		var got []*types.DNS
		(&reader{conversation: conversation}).decode(func(r *types.DNS) { got = append(got, r) })
		if len(got) != 2 || got[0].TransactionStatus != "query" || got[1].TransactionStatus != "answered" {
			t.Fatalf("split %d: %+v", split, got)
		}
		expected := int64(400)
		if split == 0 {
			expected = 300
		}
		if got[1].RTT != expected || got[1].SrcIP != "192.0.2.2" {
			t.Fatalf("split %d: %+v", split, got[1])
		}
	}
	if !probe(query) || probe([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("DNS framing probe")
	}
}

func TestTCPDNSGapInvalidatesPairing(t *testing.T) {
	query, response := framed(t, false), framed(t, true)
	gap := fragment(query[4:], 200, false)
	gap.SkippedBytes = 3
	conversation := &core.ConversationInfo{ClientIP: "192.0.2.1", ServerIP: "192.0.2.2", ClientPort: 40000, ServerPort: 53}
	conversation.Data = core.DataFragments{fragment(query[:4], 100, false), gap, fragment(response, 300, true)}
	var got []*types.DNS
	(&reader{conversation: conversation}).decode(func(r *types.DNS) { got = append(got, r) })
	if len(got) != 1 || got[0].TransactionStatus != "unsolicited" || got[0].RTT != 0 {
		t.Fatalf("paired across gap: %+v", got)
	}
}
