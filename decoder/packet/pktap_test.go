package packet

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/encoder"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

func TestPKTAPMetadata(t *testing.T) {
	data := make([]byte, 156+14+20+8)
	for offset, value := range map[int]uint32{0: 156, 4: 1, 8: 1, 36: 0x82, 40: 2, 44: 14, 48: 4, 52: 123, 76: 8, 84: 456} {
		binary.LittleEndian.PutUint32(data[offset:], value)
	}
	copy(data[12:], "en0")
	copy(data[56:], "curl")
	copy(data[88:], "shell")
	binary.LittleEndian.PutUint16(data[80:], 6)
	binary.LittleEndian.PutUint16(data[82:], 3)
	data[168], data[169] = 8, 0 // Ethernet IPv4
	data[170], data[173], data[178], data[179] = 0x45, 28, 64, 17
	copy(data[182:], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	copy(data[190:], []byte{0x9c, 0x40, 0x9c, 0x41, 0, 8, 0, 0})
	p := gopacket.NewPacket(data, layers.LayerTypePktap, gopacket.Default)
	if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeUDP) == nil {
		t.Fatalf("inner packet: %v", p)
	}
	r := pktapDecoder.Handler(p.Layer(layers.LayerTypePktap), 123456789).(*types.PKTAP)
	r.SetPacketContext(&types.PacketContext{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 40000, DstPort: 40001, CommunityID: "flow"})
	if r.HeaderLength != 156 || r.RecordType != 1 || r.DLT != 1 || r.InterfaceName != "en0" || r.Flags != 0x82 || r.ProtocolFamily != 2 || r.LinkLayerHeaderLength != 14 || r.LinkLayerTrailerLength != 4 || r.PID != 123 || r.CommandName != "curl" || r.ServiceClass != 8 || r.ServiceClassName != "VO" || r.InterfaceType != 6 || r.InterfaceUnit != 3 || r.EffectivePID != 456 || r.EffectiveCommandName != "shell" || r.Direction != "out" {
		t.Fatalf("metadata: %v", r)
	}
	if r.Src() != "192.0.2.1" || r.Dst() != "192.0.2.2" || r.CommunityID != "flow" {
		t.Fatal("context lost")
	}
	wire, err := proto.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	restored := netio.InitRecord(types.Type_NC_PKTAP)
	if err := proto.Unmarshal(wire, restored); err != nil || !proto.Equal(r, restored) {
		t.Fatalf("roundtrip: %v", err)
	}
	encoder.SetConfig(&encoder.Config{MinMax: true})
	if len(r.CSVHeader()) != len(r.CSVRecord()) || len(r.Encode()) != len(r.CSVHeader()) {
		t.Fatal("export column mismatch")
	}
	json, err := r.JSON()
	if err != nil || !strings.Contains(json, "curl") || r.Time() != 123456789 {
		t.Fatalf("JSON: %s %v", json, err)
	}
	r.Inc()
	for _, tt := range []struct {
		size           int
		header, record uint32
	}{{155, 156, 1}, {156, 155, 1}, {156, 157, 1}, {156, 156, 0}, {156, 156, 2}} {
		bad := make([]byte, tt.size)
		binary.LittleEndian.PutUint32(bad, tt.header)
		binary.LittleEndian.PutUint32(bad[4:], tt.record)
		p := gopacket.NewPacket(bad, layers.LayerTypePktap, gopacket.Default)
		if p.ErrorLayer() == nil || p.Layer(layers.LayerTypePktap) != nil {
			t.Fatalf("accepted malformed metadata %+v", tt)
		}
	}
}
