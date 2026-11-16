package collector

import (
	"encoding/binary"
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/bacnet"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/gopacket/gopacket"
	"testing"
)

func TestMSTPNPDUDispatchRequiresValidChecksums(t *testing.T) {
	body := []byte{1, 0, 0x10, 8}
	wire := []byte{0x55, 0xff, 6, 2, 1, 0, byte(len(body)), 0}
	wire[7] = mstpHeaderCRC(wire[2:7])
	wire = append(wire, body...)
	wire = binary.LittleEndian.AppendUint16(wire, mstpDataCRC(body))
	for _, bad := range []bool{false, true} {
		data := append([]byte(nil), wire...)
		if bad {
			data[len(data)-1] ^= 1
		}
		p := gopacket.NewPacket(data, captureBusDecoder(165), gopacket.Default)
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer())
		}
		f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
		if bad {
			if _, ok := f.Fields["bacnet_npdu"]; ok {
				t.Fatal("corrupt MS/TP trusted as BACnet")
			}
			continue
		}
		var parsed bacnet.PDU
		if err := json.Unmarshal([]byte(f.Fields["bacnet_npdu"]), &parsed); err != nil || parsed.APDU == nil || *parsed.APDU.Service != 8 || f.PayloadProtocol != "BACnet-NPDU" || p.NetworkLayer() != nil {
			t.Fatal(f, err)
		}
	}
}
