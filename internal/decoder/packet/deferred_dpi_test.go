package packet

import (
	"bytes"
	"testing"
	"time"

	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestDeferredDPIPreservesPerPacketView(t *testing.T) {
	old := GetBaseLayerType()
	t.Cleanup(func() { SetBaseLayerType(old) })
	for _, ethernet := range []bool{false, true} {
		wire := testutil.TCP(false, false, 10, 0, "A", "owned DPI bytes")
		base := layers.LayerTypeIPv4
		if ethernet {
			wire, base = testutil.Ethernet(wire), layers.LayerTypeEthernet
		}
		packet := gopacket.NewPacket(wire, base, gopacket.NoCopy)
		context := &packetview.Context{Scope: "if:7/vxlan:reviewed"}
		packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(0, 123), CaptureLength: len(wire), Length: len(wire), InterfaceIndex: 7, AncillaryData: []any{context}}
		buffer := bufferDPIPacket(packet)
		want := append([]byte(nil), wire...)
		wire[len(wire)-1] ^= 0xff
		SetBaseLayerType(layers.LayerTypeIPv6)
		decoded := buffer.packet()
		if decoded.ErrorLayer() != nil || decoded.TransportLayer() == nil || decoded.Layers()[0].LayerType() != base || !bytes.Equal(decoded.Data(), want) || decoded.Metadata().Timestamp.UnixNano() != 123 || decoded.Metadata().InterfaceIndex != 7 || packetview.Scope(decoded) != context.Scope {
			t.Fatalf("deferred packet lost its normalized view: %v %+v", decoded, decoded.Metadata())
		}
	}
}

func TestHostDoesNotRetainPayloadWithoutDPI(t *testing.T) {
	if dpi.IsEnabled() {
		t.Skip("requires DPI disabled")
	}
	p := testutil.Packet(testutil.Ethernet(testutil.TCP(false, false, 1, 0, "A", "unused payload")), 0, 1)
	i := decoderutils.NewPacketInfo(p)
	host := createNewHost(i.SrcIP, i, true)
	if len(host.streamPackets) != 0 || host.NumPackets != 1 || host.Bytes == 0 {
		t.Fatalf("disabled DPI retained payload or lost host accounting: %+v", host)
	}
	// Updating an existing host must obey the same ownership rule.
	hosts.Lock()
	old, existed := hosts.Items[i.SrcIP]
	hosts.Items[i.SrcIP] = host
	hosts.Unlock()
	t.Cleanup(func() {
		hosts.Lock()
		defer hosts.Unlock()
		if existed {
			hosts.Items[i.SrcIP] = old
		} else {
			delete(hosts.Items, i.SrcIP)
		}
	})
	updateHost(i.SrcIP, i, true)
	if len(host.streamPackets) != 0 || host.NumPackets != 2 || host.Bytes != uint64(2*len(p.Data())) {
		t.Fatalf("disabled DPI update retained payload or lost accounting: %+v", host)
	}
}
