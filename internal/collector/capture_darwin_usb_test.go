package collector

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func darwinUSBFrame(request, endpoint, transfer byte, body []byte) []byte {
	header := make([]byte, 32)
	binary.LittleEndian.PutUint16(header, 0x0100)
	header[2], header[3], header[28], header[29], header[30], header[31] = 32, request, 3, 7, endpoint, transfer
	binary.LittleEndian.PutUint32(header[4:], uint32(len(body)))
	binary.LittleEndian.PutUint64(header[16:], 0x1122334455667788)
	binary.LittleEndian.PutUint32(header[24:], 0x1a110000)
	return append(header, body...)
}

func TestDarwinUSBOriginalCaptures(t *testing.T) {
	urls := strings.Fields(os.Getenv("NETCAP_USB_CAPTURE_URLS"))
	if len(urls) == 0 {
		t.Skip("set NETCAP_USB_CAPTURE_URLS to the two pinned original capture URLs")
	}
	if len(urls) != 2 {
		t.Fatal("qualification requires both pinned captures")
	}
	witnesses := map[string]int{
		"5508d9d85b10a5bf947b3986c1b5dd3555bfce6dccbb4902e5c307ffec36709d": 515,
		"439bc8a580e4fb8a4c5880fc75d7ad156c0c229f0dedf786b4b8495b846e7b28": 458,
	}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, source := range urls {
		resp, err := client.Get(source)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			t.Fatal("capture retrieval failed", resp.Status)
		}
		compressed, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := io.ReadAll(io.LimitReader(reader, 8<<20))
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(wire)
		key := hex.EncodeToString(digest[:])
		want, ok := witnesses[key]
		if !ok {
			t.Fatal("capture digest is not pinned", key)
		}
		delete(witnesses, key)
		var order binary.ByteOrder
		var links []uint16
		type usbKey struct {
			id               uint64
			device, endpoint byte
		}
		wantRecords := make(map[usbKey]int)
		count := 0
		for offset := 0; offset < len(wire); {
			if len(wire)-offset < 12 {
				t.Fatal("short capture block")
			}
			block := wire[offset:]
			if bytes.Equal(block[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
				if len(block) < 28 {
					t.Fatal("short section header")
				}
				order = binary.LittleEndian
				if order.Uint32(block[8:12]) != 0x1a2b3c4d {
					order = binary.BigEndian
				}
				if order.Uint32(block[8:12]) != 0x1a2b3c4d {
					t.Fatal("invalid section byte order")
				}
				links = nil
			}
			if order == nil {
				t.Fatal("capture does not start with a section")
			}
			size := int(order.Uint32(block[4:8]))
			if size < 12 || size > len(block) || size%4 != 0 || order.Uint32(block[size-4:size]) != uint32(size) {
				t.Fatal("invalid capture block length")
			}
			block = block[:size]
			switch order.Uint32(block[:4]) {
			case 1:
				if size < 20 {
					t.Fatal("short interface block")
				}
				links = append(links, order.Uint16(block[8:10]))
			case 6:
				if size < 32 {
					t.Fatal("short packet block")
				}
				id, captured := int(order.Uint32(block[8:12])), int(order.Uint32(block[20:24]))
				if id >= len(links) || links[id] != 266 || captured > size-32 {
					t.Fatal("invalid USB packet block")
				}
				packet := decodeDarwinUSB(block[28 : 28+captured])
				if packet.ErrorLayer() != nil {
					t.Fatal("original packet rejected", count+1, packet.ErrorLayer().Error())
				}
				count++
				header := block[28 : 28+captured]
				wantRecords[usbKey{binary.LittleEndian.Uint64(header[16:24]), header[29], header[30] & 0x7f}]++
			}
			offset += size
		}
		if count != want {
			t.Fatal("original packet coverage changed", count, want)
		}
		path := filepath.Join(t.TempDir(), "original.pcapng")
		if err := os.WriteFile(path, wire, 0600); err != nil {
			t.Fatal(err)
		}
		out := t.TempDir()
		cfg := ultimateCaptureConfig(out, 1, 0)
		cfg.CaptureEvidence = true
		cfg.DecoderConfig.IncludeDecoders = "USB"
		if err := New(cfg).CollectPcapNG(path); err != nil {
			t.Fatal(err)
		}
		rows := bookRecords(t, out, "USB", func() *types.USB { return new(types.USB) })
		if len(rows) != want {
			t.Fatal("exported USB count", len(rows), want)
		}
		for _, row := range rows {
			k := usbKey{row.ID, byte(row.DeviceAddress), byte(row.EndpointNumber)}
			if wantRecords[k] == 0 {
				t.Fatalf("unexpected exported USB transfer: %+v", k)
			}
			wantRecords[k]--
		}
		manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
		if manifest.InputSHA256 != key || manifest.Status != "done" || manifest.AdmittedPackets != uint64(want) {
			t.Fatal("unexpected capture manifest", manifest.Status, manifest.AdmittedPackets)
		}
		stage, _, err := evidence.ReadAuditStage(out, manifest.RunID, "USB", manifest.AuditStagesGeneration)
		if err != nil || stage.Records != int64(want) || stage.Coverage != "complete" {
			t.Fatal(stage, err)
		}
		t.Logf("capture sha256=%s decoded=%d exported=%d", key, count, len(rows))
	}
	if len(witnesses) != 0 {
		t.Fatal("original capture qualification incomplete")
	}
}

func decodeDarwinUSB(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		return decodeCaptureUSB(data, p, 266, binary.BigEndian)
	}), gopacket.Default)
}

func TestDarwinUSBHeaderMappingAndSetup(t *testing.T) {
	for _, tc := range []struct {
		wire     []byte
		transfer layers.USBTransportType
		setup    bool
		payload  []byte
	}{
		{darwinUSBFrame(1, 0x82, 2, []byte("usb")), layers.USBTransportTypeBulk, false, []byte("usb")},
		{darwinUSBFrame(0, 0x00, 0, []byte{0x80, 6, 0, 1, 0, 0, 18, 0}), layers.USBTransportTypeControl, true, nil},
		{darwinUSBFrame(1, 0x81, 3, []byte{1, 2, 3}), layers.USBTransportTypeInterrupt, false, []byte{1, 2, 3}},
	} {
		p := decodeDarwinUSB(tc.wire)
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer().Error())
		}
		u := p.Layer(layers.LayerTypeUSB).(*layers.USB)
		if u.ID != 0x1122334455667788 || u.BusID != 26 || u.DeviceAddress != 7 || u.TransferType != tc.transfer || u.Setup != tc.setup || !bytes.Equal(u.Payload, tc.payload) {
			t.Fatal("Darwin header fields shifted or payload changed", u)
		}
		if tc.setup && p.Layer(layers.LayerTypeUSBRequestBlockSetup) == nil {
			t.Fatal("Darwin setup request missing")
		}
		if tc.wire[30]&0x80 != 0 && u.Direction != layers.USBDirectionTypeIn {
			t.Fatal("endpoint direction lost", u.Direction)
		}
		if !bytes.Equal(p.Data(), tc.wire) {
			t.Fatal("Darwin decoding rewrote capture bytes")
		}
	}
}

func TestDarwinUSBISODescriptorBounds(t *testing.T) {
	for _, complete := range []bool{false, true} {
		header := 20
		request := byte(0)
		if complete {
			header, request = 28, 1
		}
		var body []byte
		for i := range 2 {
			desc := make([]byte, header)
			binary.LittleEndian.PutUint32(desc, uint32(header))
			binary.LittleEndian.PutUint32(desc[4:], 3)
			binary.LittleEndian.PutUint64(desc[12:], uint64(i))
			body = append(body, desc...)
			if complete {
				body = append(body, 1, 2, 3)
				body = append(body, 0)
			}
		}
		wire := darwinUSBFrame(request, 0x81, 1, body)
		binary.LittleEndian.PutUint32(wire[12:], 2)
		p := decodeDarwinUSB(wire)
		if p.ErrorLayer() != nil || p.Layer(layers.LayerTypeUSB).(*layers.USB).IsoNumDesc != 2 {
			t.Fatal("valid Darwin ISO rejected", p.ErrorLayer())
		}
		binary.LittleEndian.PutUint32(wire[12:], 3)
		if decodeDarwinUSB(wire).ErrorLayer() == nil {
			t.Fatal("overclaimed ISO frames accepted")
		}
	}
	for _, wire := range [][]byte{nil, make([]byte, 31), darwinUSBFrame(0, 0, 0, []byte{1}), darwinUSBFrame(2, 0, 2, nil), darwinUSBFrame(1, 0x70, 2, nil)} {
		if decodeDarwinUSB(wire).ErrorLayer() == nil {
			t.Fatal("malformed Darwin USB accepted", wire)
		}
	}
}

func TestDarwinUSBExtendedHeaderPreservesOpaqueBytes(t *testing.T) {
	for _, size := range []int{40, 48} {
		wire := darwinUSBFrame(1, 0x81, 3, []byte{1, 2, 3})
		extension := bytes.Repeat([]byte{0xa5}, size-32)
		wire = append(append(wire[:32:32], extension...), wire[32:]...)
		binary.LittleEndian.PutUint16(wire, 0x0101)
		wire[2] = byte(size)
		p := decodeDarwinUSB(wire)
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer().Error())
		}
		u := p.Layer(layers.LayerTypeUSB).(*layers.USB)
		if !bytes.Equal(u.Contents[32:], extension) || !bytes.Equal(u.Payload, []byte{1, 2, 3}) || u.ID != 0x1122334455667788 {
			t.Fatal("extended header changed evidence", u)
		}
		for _, header := range []byte{0, 31, 32, 39, byte(len(wire) + 1)} {
			bad := bytes.Clone(wire)
			bad[2] = header
			if decodeDarwinUSB(bad).ErrorLayer() == nil {
				t.Fatalf("accepted header length %d", header)
			}
		}
		for _, version := range []uint16{0, 0x0102, 0x0200} {
			bad := bytes.Clone(wire)
			binary.LittleEndian.PutUint16(bad, version)
			if decodeDarwinUSB(bad).ErrorLayer() == nil {
				t.Fatalf("accepted version %04x", version)
			}
		}
	}
}
