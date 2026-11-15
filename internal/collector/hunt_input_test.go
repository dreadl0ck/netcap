package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestHuntInputProcess(t *testing.T) {
	input := os.Getenv("NETCAP_HUNT_INPUT")
	if input == "" {
		return
	}
	out := os.Getenv("NETCAP_HUNT_OUT")
	cfg := ultimateCaptureConfig(out, 2, 0)
	cfg.DecoderConfig.IncludeDecoders = "HTTP,Connection,IPv4,IPv6,TCP,UDP,DNS,Dot11,Alert,USB,USBRequestBlockSetup,Service"
	cfg.DecoderConfig.ExcludeDecoders = ""
	cfg.NetworkDetection, cfg.CaptureEvidence = true, true
	cfg.MergePCAPNGSections = os.Getenv("NETCAP_HUNT_MODE") == "merge"
	cfg.DecoderConfig.DefragIPv4 = os.Getenv("NETCAP_HUNT_MODE") != "no-defrag"
	c := New(cfg)
	collect := c.CollectPcap
	if isPCAPNG(t, input) {
		collect = c.CollectPcapNG
	}
	err := collect(input)
	result := inputReproResult{Complete: c.captureComplete, Packets: c.admittedPackets}
	if err != nil {
		result.Error = err.Error()
	}
	writeInputJSON(t, filepath.Join(out, "hunt-result.json"), result)
}

func runHuntInput(t *testing.T, data []byte, mode string) string {
	t.Helper()
	root := t.TempDir()
	input, out := filepath.Join(root, "input.pcap"), filepath.Join(root, "out")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHuntInputProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "NETCAP_HUNT_INPUT="+input, "NETCAP_HUNT_OUT="+out, "NETCAP_HUNT_MODE="+mode)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture: %v\n%s", err, output)
	}
	var result inputReproResult
	readInputJSON(t, filepath.Join(out, "hunt-result.json"), &result)
	if result.Error != "" || !result.Complete {
		t.Fatalf("input result: %+v", result)
	}
	return out
}

func huntPCAP(link layers.LinkType, frames ...[]byte) []byte {
	data := inputPCAPHeader(binary.LittleEndian, false, 65535, link)
	for i, frame := range frames {
		data = append(data, inputPCAPRecord(binary.LittleEndian, uint32(1700000000+i), 0, uint32(len(frame)), uint32(len(frame)), frame)...)
	}
	return data
}

func TestHuntWirelessWithoutFCS(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	header := func(control, flags byte) []byte {
		return []byte{control, flags, 0, 0, 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 3, 0, 0}
	}
	ack := header(0xd4, 0)[:10]
	cts := header(0xc4, 0)[:10]
	disassoc := append(header(0xa0, 0), 7, 0)
	beacon := append(header(0x80, 0), make([]byte, 12)...)
	beacon = append(beacon, 0, 9)
	beacon = append(beacon, []byte("Ment0rNet")...)
	beacon = append(beacon, 221, 4, 1, 2, 3, 4)
	wep := append(header(0x08, 0x40), 1, 2, 3, 0x80, 0xaa, 0xbb, 0xcc, 0xdd)
	for _, fcs := range []bool{false, true} {
		frames := [][]byte{ack, cts, disassoc, beacon, wep}
		if fcs {
			for i, frame := range frames {
				frames[i] = binary.LittleEndian.AppendUint32(bytes.Clone(frame), crc32.ChecksumIEEE(frame))
			}
		}
		data := huntPCAP(105, frames...)
		if fcs {
			binary.LittleEndian.PutUint32(data[20:], 105|0x04000000|2<<28)
		}
		out := runHuntInput(t, data, "")
		var report CaptureInputReport
		readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
		if report.LinkErrors != 0 || report.DecodeErrors != 0 || report.ProcessedPackets != 5 {
			t.Fatal(report)
		}
		records := bookRecords(t, out, "Dot11", func() *types.Dot11 { return new(types.Dot11) })
		if len(records) != 5 {
			t.Fatal("wireless frames lost", len(records))
		}
		seenSSID, seenIV, seenReason := false, false, false
		for _, r := range records {
			if r.FCSPresent != fcs || fcs && !r.FCSKnown {
				t.Fatal("FCS provenance", r)
			}
			if r.SSID != "" {
				seenSSID = true
				if r.SSID != "Ment0rNet" || !bytes.Equal(r.SSIDRaw, []byte("Ment0rNet")) || len(r.InformationElements) != 2 {
					t.Fatal(r)
				}
			}
			if len(r.WEPIV) > 0 {
				seenIV = true
				if !bytes.Equal(r.WEPIV, []byte{1, 2, 3}) || r.WEPKeyID != 2 || r.SubtypeName != "Data" {
					t.Fatal(r)
				}
			}
			if r.IsDisassociation {
				seenReason = true
				if r.ReasonCode != 7 {
					t.Fatal(r)
				}
			}
			if len(r.CSVHeader()) != len(r.CSVRecord()) || len(r.CSVHeader()) != len(r.Encode()) {
				t.Fatal("wireless CSV alignment")
			}
		}
		if !seenSSID || !seenIV || !seenReason {
			t.Fatal("wireless metadata missing")
		}
	}
}

func TestHuntFragmentDiagnosticsAndDefragSwitch(t *testing.T) {
	ip := testutil.TCP(false, false, 1, 1, "AP", "GET /fragment HTTP/1.1\r\nHost: fixture.test\r\n\r\n")
	first := testutil.Fragment(ip, 7, 0, 16, true)
	middle := testutil.Fragment(ip, 7, 16, 32, true)
	conflict := bytes.Clone(middle)
	conflict[len(conflict)-1] ^= 1
	last := testutil.Fragment(ip, 7, 32, len(ip)-20, false)
	out := runHuntInput(t, huntPCAP(1, testutil.Ethernet(first), testutil.Ethernet(middle), testutil.Ethernet(conflict), testutil.Ethernet(last)), "")
	var stats packetview.Stats
	readInputJSON(t, filepath.Join(out, "packet-normalization.json"), &stats)
	if stats.ConflictingOverlaps != 1 || stats.Rejected != 1 {
		t.Fatal(stats)
	}
	alerts := bookRecords(t, out, "Alert", func() *types.Alert { return new(types.Alert) })
	if len(alerts) != 1 || alerts[0].Name != "ip.fragment-overlap-conflict" {
		t.Fatal(alerts)
	}
	plain := huntPCAP(1, testutil.Ethernet(testutil.Fragment(ip, 8, 0, 8, true)), testutil.Ethernet(testutil.Fragment(ip, 8, 8, len(ip)-20, false)))
	for _, mode := range []string{"", "no-defrag"} {
		out = runHuntInput(t, plain, mode)
		readInputJSON(t, filepath.Join(out, "packet-normalization.json"), &stats)
		if mode == "" {
			if stats.Completed != 1 || stats.TinyFragments != 1 {
				t.Fatal(stats)
			}
			records := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
			if len(records) != 1 || records[0].URL != "/fragment" {
				t.Fatal(records)
			}
		} else if stats.IPv4DefragDisabled != 2 || stats.Completed != 0 {
			t.Fatal(stats)
		}
	}
}

func TestHuntPCAPNGContinuityAndMissingTime(t *testing.T) {
	request := testutil.Ethernet(testutil.TCP(false, false, 1, 1, "AP", "GET /sections HTTP/1.1\r\nHost: fixture.test\r\n\r\n"))
	response := testutil.Ethernet(testutil.TCP(false, true, 1, 1, "AP", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	data := append(inputNGSection(binary.LittleEndian), inputNGInterface(binary.LittleEndian, 1, 65535)...)
	data = append(data, inputNGPacket(binary.LittleEndian, 0, uint32(len(request)), uint32(len(request)), request)...)
	data = append(data, inputNGSection(binary.BigEndian)...)
	data = append(data, inputNGInterface(binary.BigEndian, 1, 65535)...)
	data = append(data, inputNGPacket(binary.BigEndian, 0, uint32(len(response)), uint32(len(response)), response)...)
	for _, mode := range []string{"", "merge"} {
		out := runHuntInput(t, data, mode)
		connections := bookRecords(t, out, "Connection", func() *types.Connection { return new(types.Connection) })
		http := bookRecords(t, out, "HTTP", func() *types.HTTP { return new(types.HTTP) })
		if mode == "merge" {
			if len(connections) != 1 || len(http) != 1 || http[0].Method != "GET" || http[0].StatusCode != 200 {
				t.Fatal("section continuity lost", connections, http)
			}
		} else if len(connections) != 2 || len(http) != 2 {
			t.Fatal("independent sections merged", connections, http)
		}
	}
	query := testutil.Ethernet(testutil.IP(false, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 53000, DstPort: 53}, &layers.DNS{ID: 7, Questions: []layers.DNSQuestion{{Name: []byte("missing-time.test"), Type: 1, Class: 1}}})))
	data = append(inputNGSection(binary.LittleEndian), inputNGInterface(binary.LittleEndian, 1, 65535)...)
	for range 8 {
		body := binary.LittleEndian.AppendUint32(nil, uint32(len(query)))
		body = append(body, query...)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		data = append(data, inputNGBlock(binary.LittleEndian, 3, body)...)
	}
	out := runHuntInput(t, data, "")
	var report CaptureInputReport
	readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
	if report.ProcessedPackets != 8 || report.MissingTimestamps != 8 || report.ReadErrors != 0 || report.Unsupported != 0 {
		t.Fatal(report)
	}
	records := bookRecords(t, out, "DNS", func() *types.DNS { return new(types.DNS) })
	if len(records) != 8 {
		t.Fatal("SPBs dropped", len(records))
	}
	for _, record := range records {
		if record.Timestamp != 0 {
			t.Fatal("invented timestamp", record)
		}
	}
}

func TestHuntKuznetzovAndFormatDiagnostics(t *testing.T) {
	frame := rawPacketFixture(t, false, 64)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data := inputPCAPHeader(order, false, 65535, 1)
		order.PutUint32(data, 0xa1b2cd34)
		record := inputPCAPRecord(order, 1700000000, 1500000, uint32(len(frame)), uint32(len(frame)), nil)
		record = append(record, make([]byte, 8)...)
		record = append(record, frame...)
		data = append(data, record...)
		report, packets, infos := scanInputBytes(t, data, false, true)
		if report.ProcessedPackets != 1 || report.ReadErrors != 0 || report.NormalizedTimestamps != 1 || !bytes.Equal(packets[0], frame) || !infos[0].Timestamp.Equal(time.Unix(1700000001, 500000000)) {
			t.Fatal(report, infos)
		}
	}
	corrupt := inputNGSection(binary.LittleEndian)
	corrupt[0] ^= 1
	for _, tc := range []struct {
		data    []byte
		message string
	}{
		{nil, "empty capture input"}, {[]byte("bad"), "truncated capture header"},
		{corrupt, "corrupt PCAPNG section header magic"}, {bytes.Repeat([]byte{0xaa}, 32), "InfoVista 5View"},
		{[]byte("unknown-format-header"), "unrecognized capture format"},
	} {
		path := filepath.Join(t.TempDir(), "input.pcap")
		if err := os.WriteFile(path, tc.data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := IsPcap(path); err == nil || !strings.Contains(err.Error(), tc.message) {
			t.Fatalf("%q: %v", tc.message, err)
		}
	}
}

func TestHuntDNSMalformedAndBinaryEvidence(t *testing.T) {
	name := []byte{0xff, 0x80, 'x', '.', 't', 'e', 's', 't'}
	malformed := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}
	question := &layers.DNS{ID: 8, Questions: []layers.DNSQuestion{{Name: name, Type: 16, Class: 1}}}
	answer := &layers.DNS{ID: 8, QR: true, Answers: []layers.DNSResourceRecord{{Name: name, Type: 16, Class: 1, TTL: 60, TXTs: [][]byte{[]byte("plain text"), {0xff, 0, 0x80}}}}}
	wrap := func(payload []byte) []byte {
		return testutil.Ethernet(testutil.IP(false, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 53000, DstPort: 53}, gopacket.Payload(payload))))
	}
	data := huntPCAP(1, wrap(malformed), wrap(testutil.Serialize(question)), wrap(testutil.Serialize(answer)))
	out := runHuntInput(t, data, "")
	var report CaptureInputReport
	readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
	if report.DecodeErrors != 1 || report.ProcessedPackets != 3 {
		t.Fatal(report)
	}
	records := bookRecords(t, out, "DNS", func() *types.DNS { return new(types.DNS) })
	if len(records) != 3 {
		t.Fatal("DNS messages silently dropped", len(records))
	}
	bad, query, txt := false, false, false
	for _, r := range records {
		if r.ParseError != "" {
			bad = true
			if r.ParseStatus != "partial" || !bytes.Equal(r.RawMessage, malformed) {
				t.Fatal(r)
			}
		}
		if len(r.Questions) > 0 {
			query = true
			if !bytes.Equal(r.Questions[0].NameRaw, name) || !strings.Contains(r.Questions[0].Name, `\xff`) {
				t.Fatal(r)
			}
		}
		if len(r.Answers) > 0 {
			txt = true
			rr := r.Answers[0]
			if rr.IP != "" || len(rr.TXTStrings) != 2 || rr.TXTStrings[0] != "plain text" || !bytes.Equal(rr.TXTs[1], []byte{0xff, 0, 0x80}) {
				t.Fatal(r)
			}
		}
		encoded, err := json.Marshal(r)
		if err != nil || bytes.Contains(encoded, []byte("\ufffd")) {
			t.Fatal("lossy JSON", string(encoded), err)
		}
	}
	if !bad || !query || !txt {
		t.Fatal("missing DNS evidence")
	}
}

func TestHuntUSBCaptureHeaders(t *testing.T) {
	for _, link := range []layers.LinkType{189, 220, 249} {
		var frame []byte
		if link == 249 {
			frame = make([]byte, 28)
			binary.LittleEndian.PutUint16(frame, 28)
			binary.LittleEndian.PutUint64(frame[2:], 123)
			binary.LittleEndian.PutUint16(frame[17:], 2)
			binary.LittleEndian.PutUint16(frame[19:], 7)
			frame[22] = 2
			binary.LittleEndian.PutUint32(frame[23:], 8)
			frame = append(frame, 0x80, 6, 0, 1, 0, 0, 18, 0)
		} else {
			header := 48
			if link == 220 {
				header = 64
			}
			frame = make([]byte, header)
			binary.LittleEndian.PutUint64(frame, 123)
			frame[8], frame[9], frame[11] = 'S', 2, 7
			binary.LittleEndian.PutUint16(frame[12:], 2)
			copy(frame[40:], []byte{0x80, 6, 0, 1, 0, 0, 18, 0})
		}
		out := runHuntInput(t, huntPCAP(link, frame), "")
		usb := bookRecords(t, out, "USB", func() *types.USB { return new(types.USB) })
		setup := bookRecords(t, out, "USBRequestBlockSetup", func() *types.USBRequestBlockSetup { return new(types.USBRequestBlockSetup) })
		if len(usb) != 1 || len(setup) != 1 {
			t.Fatal(link, "USB audit records missing", usb, setup)
		}
		if usb[0].ID != 123 || usb[0].DeviceAddress != 7 || usb[0].BusID != 2 {
			t.Fatal(link, usb[0])
		}
		for size := 0; size < len(frame); size++ {
			p := gopacket.NewPacket(frame[:size], gopacket.DecodeFunc(func(data []byte, b gopacket.PacketBuilder) error {
				return decodeCaptureUSB(data, b, link, binary.LittleEndian)
			}), gopacket.Default)
			_ = p.ErrorLayer()
		}
	}
}

func TestHuntUDPServiceEvidence(t *testing.T) {
	reply := testutil.Serialize(&layers.DNS{ID: 7, QR: true})
	packet := testutil.Ethernet(testutil.IP(false, true, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 137, DstPort: 53000}, gopacket.Payload(reply))))
	out := runHuntInput(t, huntPCAP(1, packet), "")
	services := bookRecords(t, out, "Service", func() *types.Service { return new(types.Service) })
	if len(services) != 1 || services[0].IP != "10.0.0.2" || services[0].Port != 137 {
		t.Fatal("reply-first ephemeral service", services)
	}
	probe := testutil.IP(false, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: 53000, DstPort: 9999}, gopacket.Payload("probe")))
	refused := testutil.IP(false, true, layers.IPProtocolICMPv4, testutil.Serialize(&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}, gopacket.Payload(probe[:28])))
	out = runHuntInput(t, huntPCAP(1, testutil.Ethernet(probe), testutil.Ethernet(refused)), "")
	if _, err := os.Stat(filepath.Join(out, "Service.ncap")); !os.IsNotExist(err) {
		t.Fatal("closed UDP port became an observed service", err)
	}
}
