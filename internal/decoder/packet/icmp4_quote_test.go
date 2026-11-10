package packet

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"
)

func TestICMPv4QuotationIsEvidenceNotAnObservedPeer(t *testing.T) {
	previous := conf
	conf = &config.Config{}
	t.Cleanup(func() { conf = previous })
	quoted := testutil.IP(false, false, layers.IPProtocolUDP, make([]byte, 64))
	for _, kind := range []uint8{3, 4, 5, 8, 11, 12} {
		for _, size := range []int{19, 20, len(quoted)} {
			wire := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(kind, 0), BaseLayer: layers.BaseLayer{Payload: quoted[:size]}}
			r := icmpv4Decoder.Handler(wire, 42).(*types.ICMPv4)
			if kind == 8 || size < 20 {
				if r.QuotedSrcIP != "" || r.QuotedDstIP != "" || r.QuotedIPProtocol != 0 {
					t.Fatal("echo data or a truncated quote became an IP assertion", r)
				}
				continue
			}
			r.SetPacketContext(&types.PacketContext{SrcIP: "192.0.2.1", DstIP: "192.0.2.2"})
			if r.QuotedSrcIP != "10.0.0.1" || r.QuotedDstIP != "10.0.0.2" || r.QuotedIPProtocol != 17 || r.Src() != "192.0.2.1" || r.Dst() != "192.0.2.2" {
				t.Fatal(r)
			}
			data, err := proto.Marshal(r)
			var decoded types.ICMPv4
			if err != nil || proto.Unmarshal(data, &decoded) != nil || !proto.Equal(r, &decoded) {
				t.Fatal("quotation did not round-trip through protobuf", err)
			}
			data, err = json.Marshal(r)
			if err != nil || !strings.Contains(string(data), `"QuotedDstIP":"10.0.0.2"`) || len(r.CSVHeader()) != len(r.CSVRecord()) {
				t.Fatal("quotation format mismatch", err, string(data))
			}
		}
	}
}
