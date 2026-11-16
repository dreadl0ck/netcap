package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func axAddress(call string, final bool) []byte {
	a := make([]byte, 7)
	for i := range 6 {
		a[i] = ' ' << 1
		if i < len(call) {
			a[i] = call[i] << 1
		}
	}
	a[6] = 0x60
	if final {
		a[6]++
	}
	return a
}

func upperTag(kind uint16, value []byte) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, kind)
	binary.BigEndian.PutUint16(b[2:], uint16(len(value)))
	return append(b, value...)
}

func busFixtures() map[layers.LinkType][]byte {
	ax := append(axAddress("DEST", false), axAddress("SOURCE", true)...)
	ax = append(ax, 3, 0xf0, 'h', 'i')
	ts := bytes.Repeat([]byte{0xff}, 188)
	ts[0], ts[1], ts[2], ts[3] = 0x47, 0, 0x20, 0x10
	ip := testutil.IP(false, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 40000, DstPort: 9999}, gopacket.Payload("fixture")))
	upper := append(upperTag(12, []byte("ip\x00\x00")), upperTag(20, []byte{10, 0, 0, 1})...)
	upper = append(upper, upperTag(0, nil)...)
	upper = append(upper, ip...)
	alp := []byte{byte(len(ip)>>8) & 7, byte(len(ip))}
	alp = append(alp, ip...)
	return map[layers.LinkType][]byte{
		3:   ax,
		165: {0x55, 0xff, 5, 2, 1, 0, 3, 0, 'a', 'b', 'c', 0, 0},
		187: {4, 0x0e, 1, 0},
		201: {0, 0, 0, 1, 1, 3, 0x0c, 0},
		209: {1, 0, 0, 0, 1, 0xa0, 0x42},
		243: ts,
		252: upper,
		289: alp,
		300: {0, 0xff, 0x32, 0x32},
	}
}

func TestBusFramingMetadataAndInnerIP(t *testing.T) {
	for link, wire := range busFixtures() {
		t.Run("DLT_"+strconv.Itoa(int(link)), func(t *testing.T) {
			p := gopacket.NewPacket(wire, captureBusDecoder(link), gopacket.Default)
			if p.ErrorLayer() != nil {
				t.Fatal(p.ErrorLayer().Error())
			}
			f, ok := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
			if !ok || f.Type != uint32(link) || len(f.Header) == 0 || f.Protocol == "" || !bytes.Equal(p.Data(), wire) {
				t.Fatal("missing or changed link framing", f)
			}
			if link == 252 || link == 289 {
				if p.Layer(layers.LayerTypeIPv4) == nil || p.Layer(layers.LayerTypeUDP) == nil {
					t.Fatal("declared inner IP not decoded", p)
				}
			} else if p.NetworkLayer() != nil {
				t.Fatal("bus framing invented an IP network", p)
			}
		})
	}
}

func TestBusCapturesProduceFramingRecords(t *testing.T) {
	for link, wire := range busFixtures() {
		t.Run("DLT_"+strconv.Itoa(int(link)), func(t *testing.T) {
			out := runHuntInput(t, huntPCAP(link, wire), "")
			counts, _ := ultimateRecords(t, out)
			if counts["LinkFrame"] != 1 {
				t.Fatal("valid bus packet has no framing audit", counts)
			}
			if link == 252 || link == 289 {
				if counts["IPv4"] != 1 || counts["UDP"] != 1 {
					t.Fatal("inner IP audit missing", counts)
				}
			} else if counts["IPv4"] != 0 || counts["IPv6"] != 0 {
				t.Fatal("bus packet invented network traffic", counts)
			}
		})
	}
	out := runHuntInput(t, huntPCAP(266, darwinUSBFrame(1, 0x82, 2, []byte("usb"))), "")
	counts, _ := ultimateRecords(t, out)
	if counts["USB"] != 1 {
		t.Fatal("Darwin USB audit missing", counts)
	}
}

type busFramingProbe struct {
	gopacket.PacketBuilder
	layers []gopacket.Layer
}

func (p *busFramingProbe) AddLayer(l gopacket.Layer)        { p.layers = append(p.layers, l) }
func (*busFramingProbe) NextDecoder(gopacket.Decoder) error { return nil }
func (*busFramingProbe) SetTruncated()                      {}

func TestBusFramingRejectsLengthOverclaims(t *testing.T) {
	for link, wire := range busFixtures() {
		p := gopacket.NewPacket(wire[:1], captureBusDecoder(link), gopacket.Default)
		if p.ErrorLayer() == nil {
			t.Fatal("short link header accepted", link)
		}
	}
	for _, wire := range [][]byte{upperTag(0, []byte{1}), append(upperTag(12, []byte("ip")), []byte{0, 20, 0xff, 0xff}...), {0x80, 0xff, 0, 0}, {0, 1}} {
		p := gopacket.NewPacket(wire, captureBusDecoder(252), gopacket.Default)
		if p.ErrorLayer() == nil {
			t.Fatal("invalid Upper PDU accepted", wire)
		}
	}
	p := gopacket.NewPacket([]byte{0, 40, 0x45}, captureBusDecoder(289), gopacket.Default)
	if p.ErrorLayer() == nil {
		t.Fatal("overclaimed ALP payload accepted")
	}
}

func TestMSTPChecksumsAndTrailerBounds(t *testing.T) {
	wire, err := hex.DecodeString("55ff0302010003fb616263259e")
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"valid", "header", "data"} {
		t.Run(variant, func(t *testing.T) {
			data := bytes.Clone(wire)
			if variant == "header" {
				data[7] ^= 1
			} else if variant == "data" {
				data[8] ^= 1
			}
			p := gopacket.NewPacket(data, captureBusDecoder(165), gopacket.Default)
			if p.ErrorLayer() != nil {
				t.Fatal("checksum failure lost framing", p.ErrorLayer())
			}
			f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
			if f.Fields["header_crc_valid"] != strconv.FormatBool(variant != "header") || f.Fields["data_crc_valid"] != strconv.FormatBool(variant != "data") || !bytes.Equal(p.Data(), data) {
				t.Fatal("CRC status or original bytes changed", f)
			}
		})
	}
	for _, kind := range []byte{5, 8, 32, 128} {
		data := []byte{0x55, 0xff, kind, 2, 1, 0, 5, 0, 1, 2, 3, 4, 5}
		if p := gopacket.NewPacket(data, captureBusDecoder(165), gopacket.Default); p.ErrorLayer() == nil {
			t.Fatal("MS/TP accepted missing two-byte trailer", kind)
		}
		data = append(data, 0, 0)
		p := gopacket.NewPacket(data, captureBusDecoder(165), gopacket.Default)
		if p.ErrorLayer() != nil {
			t.Fatal("complete MS/TP body rejected", kind, p.ErrorLayer())
		}
		if kind == 32 {
			f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
			if _, found := f.Fields["data_crc_valid"]; found || f.Fields["cobs_valid"] != "false" {
				t.Fatal("COBS encoded checksum was treated as CRC16", f)
			}
		}
	}
}

func TestMSTPChecksumReferenceTshark(t *testing.T) {
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark is required for independent MS/TP CRC qualification")
	}
	wire, err := hex.DecodeString("55ff0302010003fb616263259e")
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(wire)
	bad[7] ^= 1
	bad[8] ^= 1
	path := filepath.Join(t.TempDir(), "mstp.pcap")
	if err := os.WriteFile(path, huntPCAP(165, wire, bad), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(tshark, "-n", "-r", path, "-T", "fields", "-e", "mstp.checksum.status").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != "1,1\n0,0" {
		t.Fatalf("independent checksum reference disagrees: %q", output)
	}
}

func FuzzBusFramingBounds(f *testing.F) {
	for link, wire := range busFixtures() {
		f.Add(wire, uint16(link))
	}
	f.Fuzz(func(t *testing.T, wire []byte, link uint16) {
		if len(wire) > 65536 {
			t.Skip()
		}
		decoder := captureBusDecoder(layers.LinkType(link))
		if decoder == nil {
			return
		}
		probe := &busFramingProbe{}
		_ = decoder.Decode(wire, probe)
		for _, layer := range probe.layers {
			if len(layer.LayerContents())+len(layer.LayerPayload()) > len(wire) {
				t.Fatal("framing escaped capture boundary")
			}
		}
	})
}
