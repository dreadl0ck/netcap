package packet

import (
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
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

type sipScopeWriter struct {
	netio.AuditRecordWriter
	record *types.SIP
}

func (w *sipScopeWriter) Write(m proto.Message) error {
	w.record = proto.Clone(m).(*types.SIP)
	return nil
}

func TestPacketSIPCarriesImmutableScope(t *testing.T) {
	oldConfig, oldWriter, oldCount := conf, sipDecoder.writer, sipDecoder.numRecords
	conf = &config.Config{}
	w := &sipScopeWriter{}
	sipDecoder.writer = w
	t.Cleanup(func() { conf, sipDecoder.writer, sipDecoder.numRecords = oldConfig, oldWriter, oldCount })
	wire := "OPTIONS sip:a@example.test SIP/2.0\r\nFrom: <sip:a@example.test>;tag=one\r\nCall-ID: same-call\r\nContent-Length: 0\r\n\r\n"
	for _, loc := range []struct {
		iface int
		vni   uint32
	}{{1, 7}, {2, 7}, {1, 8}} {
		ip := testutil.IP(false, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 5060, DstPort: 5060}, gopacket.Payload(wire)))
		processor := packetview.New(packetview.Limits{})
		r := processor.Process(testutil.Packet(testutil.Ethernet(testutil.Tunnel("vxlan", loc.vni, ip)), loc.iface, 1), 1)
		if r.Packet == nil {
			t.Fatalf("normalization: %s", r.Status)
		}
		layer := r.Packet.Layer(layers.LayerTypeSIP)
		if layer == nil {
			t.Fatal("fixture lacks SIP layer")
		}
		// Scope comes from the immutable packet view, even without a packet context.
		if err := sipDecoder.Decode(nil, r.Packet, layer); err != nil {
			t.Fatal(err)
		}
		if w.record.NetworkScope != packetview.Scope(r.Packet) || w.record.Transport != "UDP" {
			t.Fatalf("scope/transport: %v", w.record)
		}
		ctx := &types.PacketContext{NetworkScope: "scope-control"}
		w.record.SetPacketContext(ctx)
		if w.record.NetworkScope != ctx.NetworkScope {
			t.Fatal("SIP packet context lost scope")
		}
	}
}
