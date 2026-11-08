package collector

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/encoder"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestW76VoIPProcess(t *testing.T) {
	input := os.Getenv("W76_INPUT")
	if input == "" {
		return
	}
	workers, _ := strconv.Atoi(os.Getenv("W76_WORKERS"))
	dc := config.DefaultConfig.Clone()
	dc.Out, dc.Source, dc.Quiet = os.Getenv("W76_OUT"), input, true
	dc.IncludeDecoders = os.Getenv("W76_INCLUDE")
	dc.Proto, dc.Compression, dc.IncludePayloads = true, false, false
	dc.NumStreamWorkers = workers
	c := New(Config{Workers: workers, PacketBufferSize: 8, ReassembleConnections: true,
		NoSignalHandling: true, NoPrompt: true, BaseLayer: layers.LayerTypeEthernet,
		DecodeOptions: gopacket.Default, DecoderConfig: dc, OutDirPermission: 0700})
	if err := c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
}

func runVoIP(t *testing.T, input, include string, workers int) string {
	t.Helper()
	out := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestW76VoIPProcess$", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "W76_INPUT="+input, "W76_OUT="+out, "W76_INCLUDE="+include, fmt.Sprintf("W76_WORKERS=%d", workers))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("VoIP collector: %v\n%s", err, output)
	}
	return out
}

func TestW76SIPResponseExports(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	b, input := newBookCapture(t)
	for _, status := range []string{"401 Unauthorized", "200 OK"} {
		b.udp("192.0.2.2", "192.0.2.1", 5060, 5060, []byte("SIP/2.0 "+status+"\r\nCall-ID: regression\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n"))
	}
	out := runVoIP(t, input, "SIP", 1)
	records := bookRecords(t, out, "SIP", func() *types.SIP { return new(types.SIP) })
	if len(records) != 2 {
		t.Fatalf("SIP count %d", len(records))
	}
	for i, r := range records {
		at := r.Timestamp
		code, reason := int32(401), "Unauthorized"
		if i == 1 {
			code, reason = 200, "OK"
		}
		if !r.IsResponse || r.ResponseCode != code || r.ResponseStatus != reason {
			t.Fatalf("protobuf: %v", r)
		}
		fields := map[string]string{}
		for j, h := range r.CSVHeader() {
			fields[h] = r.CSVRecord()[j]
		}
		if fields["ResponseCode"] != fmt.Sprint(code) || fields["ResponseStatus"] != reason {
			t.Fatalf("CSV: %v", fields)
		}
		encoded := r.Encode()
		for j, h := range r.CSVHeader() {
			if (h == "ResponseCode" || h == "ResponseStatus") && encoded[j] == "" {
				t.Fatalf("encoded export lost %s: %v", h, encoded)
			}
		}
		json, err := r.JSON()
		if err != nil || !strings.Contains(json, fmt.Sprintf(`"ResponseCode":%d`, code)) || !strings.Contains(json, `"ResponseStatus":"`+reason+`"`) {
			t.Fatalf("JSON: %s %v", json, err)
		}
		if r.Timestamp != at {
			t.Fatal("SIP JSON mutated timestamp")
		}
	}
}

func TestW76FC04(t *testing.T) {
	input := os.Getenv("W76_FC04")
	if input == "" {
		t.Skip("set W76_FC04 to the pinned Honeynet capture")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != "568c113747dd9adcdb24dbf7f5aff9143dd19d7027d8f84bc3e93cf9e4ceee86" {
		t.Fatal("fc04 digest mismatch")
	}
	out := runVoIP(t, input, "SIP,RTP,DTMF", 2)
	records := bookRecords(t, out, "SIP", func() *types.SIP { return new(types.SIP) })
	if len(records) != 19 {
		t.Fatalf("SIP count %d", len(records))
	}
	codes := map[int32]int{}
	for _, r := range records {
		if !r.IsResponse {
			continue
		}
		codes[r.ResponseCode]++
		if r.ResponseStatus == "" {
			t.Fatal("missing reason phrase")
		}
		csv := r.CSVRecord()
		for i, h := range r.CSVHeader() {
			if h == "ResponseCode" && csv[i] != fmt.Sprint(r.ResponseCode) {
				t.Fatal("CSV status lost")
			}
		}
		json, err := r.JSON()
		if err != nil || !strings.Contains(json, fmt.Sprintf(`"ResponseCode":%d`, r.ResponseCode)) {
			t.Fatalf("JSON: %s %v", json, err)
		}
	}
	if fmt.Sprint(codes) != "map[100:1 200:4 401:3 404:1]" {
		t.Fatalf("status counts: %v", codes)
	}
	t.Logf("19 SIP records; response codes %v; protobuf/JSON/CSV preserved", codes)
	rtp := bookRecords(t, out, "RTP", func() *types.RTP { return new(types.RTP) })
	events := bookRecords(t, out, "DTMF", func() *types.DTMF { return new(types.DTMF) })
	// tshark also labels two ICMP port-unreachable quotations as RTP (4445/4447).
	if len(rtp) != 3113 {
		t.Fatalf("RTP count %d, expected 3113 UDP packets", len(rtp))
	}
	if len(events) != 15 {
		t.Fatalf("completed telephone events %d, expected 15", len(events))
	}
	t.Logf("RTP=%d completed deduplicated DTMF=%d", len(rtp), len(events))
}

func TestW76PinnedCaptures(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, hash string
		count                int
	}{
		{"dnp3_udp_read.pcap", "DNP3", "4787acb645e088ddabfcec437c3adeee30b51a445c064b62c0a85c48280ee8ba", 23},
		{"dnp3_udp_write.pcap", "DNP3", "62ff4d916c295ab81825d3d22419c44855d528529ed72c9f76b88567f6b07219", 2},
		{"dnp3_udp_en_spon.pcap", "DNP3", "6e2d07f5ee3d5c2545456b5612565b604fcc13d9aab30192bab64ff233f2a650", 4},
		{"mdns.pcap", "DNS", "f7725d833d6b0f2c626cce8a22fc5a6f982ae4e7e4fed164b1d1ddf61d8cf137", 18},
		{"sip-tcp.pcap", "SIP", "8730ef1a0796ce186f2bd853fe41db35268d3d8c822ceb6c7da9491e03d3a667", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join("testdata", "voip", tc.name)
			data, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(data)) != tc.hash {
				t.Fatal("fixture digest mismatch")
			}
			for _, workers := range []int{1, 4} {
				out := runVoIP(t, input, tc.protocol, workers)
				switch tc.protocol {
				case "DNP3":
					records := bookRecords(t, out, tc.protocol, func() *types.DNP3 { return new(types.DNP3) })
					if len(records) != tc.count {
						t.Fatalf("count=%d expected=%d", len(records), tc.count)
					}
					functions := map[int32]bool{}
					for _, r := range records {
						if r.CommunityID != streamutils.CalcCommunityIDUDP(r.SrcIP, r.DstIP, uint16(r.SrcPort), uint16(r.DstPort)) {
							t.Fatalf("UDP attribution: %v", r)
						}
						if r.DirectionMismatch || r.ParseStatus == "malformed" || r.ParseStatus == "lost" {
							t.Fatalf("parse: %v", r)
						}
						if r.FunctionCode != 0 {
							functions[r.FunctionCode] = true
						}
					}
					request := int32(1)
					if tc.name == "dnp3_udp_write.pcap" {
						request = 2
					} else if tc.name == "dnp3_udp_en_spon.pcap" {
						request = 20
					}
					if !functions[request] || !functions[129] {
						t.Fatalf("missing request/response functions: %v", functions)
					}
				case "DNS":
					records := bookRecords(t, out, tc.protocol, func() *types.DNS { return new(types.DNS) })
					if len(records) != tc.count {
						t.Fatalf("count=%d", len(records))
					}
					for _, r := range records {
						if !strings.HasPrefix(r.TransactionStatus, "mdns_") || r.RTT != 0 || r.QueryTransmissions != 0 {
							t.Fatalf("false unicast pairing: %v", r)
						}
					}
				case "SIP":
					records := bookRecords(t, out, tc.protocol, func() *types.SIP { return new(types.SIP) })
					if len(records) != tc.count {
						t.Fatalf("count=%d", len(records))
					}
					if records[0].Transport != "TCP" || records[1].ResponseCode != 200 {
						t.Fatalf("SIP TCP: %v", records)
					}
				}
			}
		})
	}
}

func voipSDP(ip string, port int, pt int) string {
	return fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 %s\r\ns=synthetic\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio %d RTP/AVP 0 %d\r\na=rtpmap:%d telephone-event/8000\r\na=fmtp:%d 0-15\r\n", ip, ip, port, pt, pt, pt)
}

func voipSIP(start, body string) string {
	return fmt.Sprintf("%s\r\ni: call-w76\r\nf: <sip:caller@example.test>;tag=offer\r\nt: <sip:callee@example.test>\r\nv: SIP/2.0/UDP 192.0.2.1\r\nCSeq: 1 INVITE\r\nc: application/sdp\r\nl: %d\r\n\r\n%s", start, len(body), body)
}

func voipRTP(seq uint16, ts, ssrc uint32, pt byte, body []byte) []byte {
	b := make([]byte, 12)
	b[0], b[1] = 0x80, pt
	binary.BigEndian.PutUint16(b[2:], seq)
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], ssrc)
	return append(b, body...)
}

func TestW76NegotiatedMedia(t *testing.T) {
	encoder.SetConfig(&encoder.Config{ZScore: true})
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprint("TCP=", tcp), func(t *testing.T) {
			b, input := newBookCapture(t)
			offer := voipSIP("INVITE sip:callee@example.test SIP/2.0", voipSDP("192.0.2.1", 4000, 110))
			answer := voipSIP("SIP/2.0 200 OK", voipSDP("192.0.2.2", 5000, 110))
			if tcp {
				send := b.openTCP("192.0.2.1", "192.0.2.2", 45060, 5060, false)
				send(false, false, false, offer[:7])
				send(false, false, false, offer[7:])
				send(true, false, false, answer)
				// EOF owns completion; the media arrives before SIP readers drain.
			} else {
				b.udp("192.0.2.1", "192.0.2.2", 5060, 5060, []byte(offer))
				b.udp("192.0.2.2", "192.0.2.1", 5060, 5060, []byte(answer))
			}
			for _, p := range [][]byte{
				voipRTP(65535, 0xfffffff0, 42, 0, []byte{1}),
				voipRTP(0, 0x10, 42, 0, []byte{2}),
				voipRTP(65534, 0xffffffe0, 42, 0, []byte{3}),
				voipRTP(1, 0x100, 42, 110, []byte{5, 10, 0, 80}),
				voipRTP(2, 0x100, 42, 110, []byte{5, 138, 0, 160}),
				voipRTP(3, 0x100, 42, 110, []byte{5, 138, 0, 160}),
				voipRTP(4, 0x100, 42, 110, []byte{5, 138, 0, 160}),
				voipRTP(4, 0x100, 43, 110, []byte{5, 138, 0, 160}),
				voipRTP(5, 0x200, 42, 110, []byte{5, 138, 0}),        // short event
				voipRTP(6, 0x200, 42, 110, []byte{5, 202, 0, 160}),   // reserved bit
				voipRTP(7, 0x200, 42, 110, []byte{255, 138, 0, 160}), // unnegotiated event
			} {
				b.udp("192.0.2.1", "192.0.2.2", 4000, 5000, p)
			}
			b.udp("192.0.2.2", "192.0.2.1", 5000, 4000, voipRTP(9, 0x100, 42, 110, []byte{5, 138, 0, 160}))
			// Wrong tuple, unnegotiated PT, random UDP, malformed header and RTCP.
			b.udp("192.0.2.3", "192.0.2.2", 4000, 5000, voipRTP(1, 1, 42, 110, []byte{5, 138, 0, 160}))
			b.udp("192.0.2.1", "192.0.2.2", 4000, 5000, voipRTP(1, 1, 42, 101, []byte{5, 138, 0, 160}))
			b.udp("192.0.2.1", "192.0.2.2", 4000, 5000, []byte("not RTP"))
			b.udp("192.0.2.1", "192.0.2.2", 4000, 5000, []byte{0x8f, 110, 0, 1, 0, 0, 0, 0, 0, 0, 0, 42})
			b.udp("192.0.2.1", "192.0.2.2", 4000, 5000, voipRTP(1, 1, 42, 200, []byte{1}))
			var reference []string
			for _, workers := range []int{1, 4} {
				out := runVoIP(t, input, "SIP,RTP,DTMF", workers)
				sips := bookRecords(t, out, "SIP", func() *types.SIP { return new(types.SIP) })
				if len(sips) != 2 || sips[0].CallID != "call-w76" || sips[1].ResponseCode != 200 || len(sips[0].Body) != 0 {
					t.Fatalf("SIP compact/framing: %v", sips)
				}
				media := bookRecords(t, out, "RTP", func() *types.RTP { return new(types.RTP) })
				events := bookRecords(t, out, "DTMF", func() *types.DTMF { return new(types.DTMF) })
				if len(media) != 12 || len(events) != 3 {
					t.Fatalf("RTP=%d DTMF=%d", len(media), len(events))
				}
				for _, m := range media {
					if m.SSRC == 42 && m.SrcPort == 4000 && m.Sequence == 0 && (m.ExtendedSequence != 65536 || m.ExtendedTimestamp != 0x100000010) {
						t.Fatalf("wrap: %v", m)
					}
					if m.Sequence == 65534 && (!m.Reordered || m.ExtendedSequence != 65534) {
						t.Fatalf("reorder: %v", m)
					}
					if m.CommunityID != streamutils.CalcCommunityIDUDP(m.SrcIP, m.DstIP, uint16(m.SrcPort), uint16(m.DstPort)) {
						t.Fatal("RTP CommunityID")
					}
					checkVoIPExports(t, m)
				}
				var got []string
				for _, e := range events {
					checkVoIPExports(t, e)
					if e.Digit != "5" || e.Duration != 160 || e.ClockRate != 8000 {
						t.Fatalf("event: %v", e)
					}
					got = append(got, e.String())
				}
				sort.Strings(got)
				if workers == 1 {
					reference = got
				} else if !reflect.DeepEqual(reference, got) {
					t.Fatal("worker-dependent event output")
				}
			}
			out := runVoIP(t, input, "DTMF", 2)
			if events := bookRecords(t, out, "DTMF", func() *types.DTMF { return new(types.DTMF) }); len(events) != 3 {
				t.Fatal("DTMF-only selection lost signaling dependency")
			}
			out = runVoIP(t, input, "", 2)
			if events := bookRecords(t, out, "DTMF", func() *types.DTMF { return new(types.DTMF) }); len(events) != 3 {
				t.Fatal("default registry lost media")
			}
		})
	}
}

func TestW76MDNSMulticastSemantics(t *testing.T) {
	b, input := newBookCapture(t)
	question := &layers.DNS{Questions: []layers.DNSQuestion{{Name: []byte("host.local"), Type: layers.DNSTypeA, Class: layers.DNSClass(0x8001)}}}
	answer := &layers.DNS{QR: true, AA: true, Answers: []layers.DNSResourceRecord{{Name: []byte("host.local"), Type: layers.DNSTypeA, Class: layers.DNSClass(0x8001), TTL: 120, IP: []byte{192, 0, 2, 1}}}}
	wire := func(d *layers.DNS) []byte {
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, d); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	b.udp("192.0.2.1", "224.0.0.251", 5353, 5353, wire(question))
	b.udp("192.0.2.2", "224.0.0.251", 5353, 5353, wire(question))
	b.udp("192.0.2.3", "224.0.0.251", 5353, 5353, wire(answer))
	b.udp("192.0.2.3", "192.0.2.1", 5353, 5353, wire(answer)) // QU unicast response
	b.udp("192.0.2.3", "224.0.0.251", 5353, 5353, []byte{0, 0, 0, 0})
	out := runVoIP(t, input, "DNS", 4)
	records := bookRecords(t, out, "DNS", func() *types.DNS { return new(types.DNS) })
	if len(records) != 4 {
		t.Fatalf("mDNS count %d", len(records))
	}
	for _, r := range records {
		if r.RTT != 0 || r.QueryTransmissions != 0 {
			t.Fatal("multicast falsely paired")
		}
		if r.QR {
			if r.TransactionStatus != "mdns_response" || r.Answers[0].Class != 0x8001 {
				t.Fatal("cache-flush lost")
			}
		} else if r.TransactionStatus != "mdns_query" || r.Questions[0].Class != 0x8001 {
			t.Fatal("QU bit lost")
		}
	}
}

func TestW76SIPFramingControls(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprint("TCP=", tcp), func(t *testing.T) {
			b, input := newBookCapture(t)
			message := "OPTIONS sip:peer@example.test SIP/2.0\r\ni: framed\r\nf: <sip:a@example.test>;tag=one\r\nCSeq: 1 OPTIONS\r\nl: 4\r\n\r\nbody"
			if tcp {
				send := b.openTCP("192.0.2.1", "192.0.2.2", 45060, 5060, false)
				send(false, false, false, message[:9])
				send(false, false, false, message[9:]+message)
				// A duplicate compact/full length poisons framing; never resync to
				// the request-looking bytes following the ambiguous body.
				send(false, false, false, strings.Replace(message, "l: 4", "l: 4\r\nContent-Length: 4", 1)+message)
			} else {
				b.udp("192.0.2.1", "192.0.2.2", 5060, 5060, []byte(message))
				b.udp("192.0.2.1", "192.0.2.2", 5060, 5060, []byte(message))
				for _, bad := range []string{
					strings.Replace(message, "l: 4", "l: 4\r\nContent-Length: 4", 1),
					strings.Replace(message, "i: framed", "i: framed\r\nCall-ID: other", 1),
					strings.Replace(message, "l: 4", "l: 5", 1),
				} {
					b.udp("192.0.2.1", "192.0.2.2", 5060, 5060, []byte(bad))
				}
			}
			for _, workers := range []int{1, 4} {
				out := runVoIP(t, input, "SIP", workers)
				records := bookRecords(t, out, "SIP", func() *types.SIP { return new(types.SIP) })
				if len(records) != 2 {
					t.Fatalf("records=%d, expected 2", len(records))
				}
				for _, r := range records {
					if r.CallID != "framed" || r.ContentLength != 4 || r.MethodName != "OPTIONS" {
						t.Fatalf("framing: %v", r)
					}
				}
			}
		})
	}
}

func TestW76DNP3DatagramControls(t *testing.T) {
	b, input := newBookCapture(t)
	frame, err := hex.DecodeString("05640bc403000400ef7ac1c1013c0206b576")
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), frame...)
	bad[len(bad)-1] ^= 1
	for _, payload := range [][]byte{frame, frame[:12], frame[12:], bad, append(append([]byte(nil), frame...), frame...)} {
		b.udp("192.0.2.1", "192.0.2.2", 40000, 20000, payload)
	}
	for _, workers := range []int{1, 4} {
		out := runVoIP(t, input, "DNP3", workers)
		records := bookRecords(t, out, "DNP3", func() *types.DNP3 { return new(types.DNP3) })
		valid := 0
		for _, r := range records {
			if r.CommunityID != streamutils.CalcCommunityIDUDP(r.SrcIP, r.DstIP, uint16(r.SrcPort), uint16(r.DstPort)) {
				t.Fatal("TCP CommunityID on UDP")
			}
			if r.FunctionCode == 1 {
				valid++
				if !r.HeaderCRCValid || !r.BlockCRCValid {
					t.Fatalf("unchecked CRC: %v", r)
				}
			} else if r.ParseStatus != "lost" && r.ParseStatus != "malformed" {
				t.Fatalf("unqualified datagram: %v", r)
			}
		}
		if valid != 3 {
			t.Fatalf("decoded %d requests, expected 3 independent complete frames", valid)
		}
	}
}

func TestW76NegotiatedEventIntersection(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint("ambiguous=", ambiguous), func(t *testing.T) {
			b, input := newBookCapture(t)
			for _, tag := range []string{"offer", "other"} {
				if tag == "other" && !ambiguous {
					continue
				}
				offer := strings.ReplaceAll(voipSIP("INVITE sip:callee@example.test SIP/2.0", strings.ReplaceAll(voipSDP("192.0.2.1", 4000, 110), "fmtp:110 0-15", "fmtp:110 0-5")), "tag=offer", "tag="+tag)
				answer := strings.ReplaceAll(voipSIP("SIP/2.0 200 OK", strings.ReplaceAll(voipSDP("192.0.2.2", 5000, 110), "fmtp:110 0-15", "fmtp:110 5-15")), "tag=offer", "tag="+tag)
				b.udp("192.0.2.1", "192.0.2.2", 5060, 5060, []byte(offer))
				b.udp("192.0.2.2", "192.0.2.1", 5060, 5060, []byte(answer))
			}
			for _, digit := range []byte{4, 5, 6} {
				b.udp("192.0.2.1", "192.0.2.2", 4000, 5000, voipRTP(uint16(digit), uint32(digit), 42, 110, []byte{digit, 138, 0, 160}))
			}
			for _, workers := range []int{1, 4} {
				out := runVoIP(t, input, "SIP,RTP,DTMF", workers)
				if ambiguous {
					signals := bookRecords(t, out, "SIP", func() *types.SIP { return new(types.SIP) })
					if len(signals) != 4 {
						t.Fatalf("missing signaling: %d", len(signals))
					}
					for _, name := range []string{"RTP.ncap", "RTP.ncap.gz", "DTMF.ncap", "DTMF.ncap.gz"} {
						if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
							t.Fatalf("guessed ambiguous dialog: %s: %v", name, err)
						}
					}
				} else {
					events := bookRecords(t, out, "DTMF", func() *types.DTMF { return new(types.DTMF) })
					if len(events) != 1 || events[0].Digit != "5" {
						t.Fatalf("negotiated intersection: %v", events)
					}
				}
			}
		})
	}
}

func checkVoIPExports(t *testing.T, r types.AuditRecord) {
	t.Helper()
	at := r.Time()
	message := r.(proto.Message)
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	restored := netio.InitRecord(r.NetcapType())
	if restored == nil {
		t.Fatal("missing type registry")
	}
	if err := proto.Unmarshal(data, restored); err != nil || !proto.Equal(message, restored) {
		t.Fatalf("protobuf: %v", err)
	}
	text, err := r.JSON()
	if err != nil || !json.Valid([]byte(text)) {
		t.Fatalf("JSON: %s %v", text, err)
	}
	if r.Time() != at {
		t.Fatal("JSON changed capture time")
	}
	if len(r.CSVHeader()) != len(r.CSVRecord()) || len(r.CSVHeader()) != len(r.Encode()) {
		t.Fatal("export column mismatch")
	}
}
