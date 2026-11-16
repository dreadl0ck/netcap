package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/packetmeta"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func alpConcat(parts ...[]byte) []byte {
	length := 0
	for _, part := range parts {
		length += len(part)
	}
	out := []byte{0x18 | byte(length>>8&7), byte(length), byte(length>>11)<<4 | byte(len(parts)-2)<<1}
	bits := make([]byte, ((len(parts)-1)*12+7)/8)
	for i, part := range parts[:len(parts)-1] {
		for bit := 0; bit < 12; bit++ {
			if len(part)&(1<<(11-bit)) != 0 {
				pos := 12*i + bit
				bits[pos/8] |= 1 << (7 - pos%8)
			}
		}
	}
	out = append(out, bits...)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func alpSegment(data []byte, seq byte, last bool, sid, plp byte) []byte {
	flags := seq<<3 | 3
	if last {
		flags |= 4
	}
	out := []byte{0x10 | byte(len(data)>>8&7), byte(len(data)), flags, sid, 0xf1, 0, plp << 2}
	return append(out, data...)
}

func alpPacket(t *testing.T, wire []byte, iface int, stamp int64) (gopacket.Packet, *linkaudit.LinkFrame) {
	t.Helper()
	p := gopacket.NewPacket(wire, captureBusDecoder(289), gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(stamp, 0), InterfaceIndex: iface, Length: len(wire), CaptureLength: len(wire)}
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer())
	}
	return p, p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
}

func alpIPv4(port uint16) []byte {
	return testutil.IP(false, false, layers.IPProtocolUDP, testutil.Serialize(&layers.UDP{SrcPort: layers.UDPPort(port), DstPort: 9999}, gopacket.Payload("derived-packet")))
}

func TestALPConcatenationAndExtendedLength(t *testing.T) {
	for count := 2; count <= 9; count++ {
		parts := make([][]byte, count)
		for i := range parts {
			parts[i] = alpIPv4(uint16(40000 + i))
		}
		p, f := alpPacket(t, alpConcat(parts...), 1, 100)
		r := &linkReconstructor{}
		children := r.process(p, f, 7)
		if len(children) != count {
			t.Fatal(count, len(children), f)
		}
		for i, child := range children {
			if !bytes.Equal(child.Data(), parts[i]) {
				t.Fatal("component boundary changed", i)
			}
			ctx := packetview.FromCapture(child.Metadata().CaptureInfo)
			if ctx.LinkTransformations[0].ChildOrdinal != uint32(i) || len(ctx.Packets) != 1 || ctx.Packets[0].Ordinal != 7 {
				t.Fatal(ctx)
			}
			wire, err := packetmeta.Marshal(child.Metadata().CaptureInfo)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := packetmeta.Unmarshal(wire)
			got := packetview.FromCapture(restored)
			if err != nil || !reflect.DeepEqual(got.LinkTransformations, ctx.LinkTransformations) || !reflect.DeepEqual(got.Packets, ctx.Packets) || !got.CompletedAt.Equal(ctx.CompletedAt) || got.Scope != ctx.Scope {
				t.Fatal("derived metadata lost across backing", err)
			}
			if n, b, _, _ := packetview.Accounting(child); n != 1 || b != int64(len(parts[i])) {
				t.Fatal("wire accounting duplicated", n, b)
			}
		}
	}
	data := bytes.Repeat([]byte{1}, 3000)
	data[0] = 0x45
	binary.BigEndian.PutUint16(data[2:], 3000)
	wire := append([]byte{0x0b, 0xb8, 0x0c}, data...)
	_, f := alpPacket(t, wire, 1, 100)
	if f.ALP.Length != 3000 {
		t.Fatal("extended length LSB/MSB order", f.ALP.Length)
	}
	bad := alpConcat(alpIPv4(40000), alpIPv4(40001))
	bad[4] |= 1
	if p := gopacket.NewPacket(bad, captureBusDecoder(289), gopacket.Default); p.ErrorLayer() == nil {
		t.Fatal("nonzero packed padding accepted")
	}
}

func TestALPInsidePPIPreservesAbsoluteSourceRanges(t *testing.T) {
	first, second := alpIPv4(40000), alpIPv4(40001)
	wire := inputPPI(192, nil, inputPPI(289, nil, alpConcat(first, second)))
	p := inputDecode(wire, 192, binary.LittleEndian)
	f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
	r := &linkReconstructor{}
	children := r.process(p, f, 1)
	if len(children) != 2 || !bytes.Equal(children[0].Data(), first) || !bytes.Equal(children[1].Data(), second) {
		t.Fatal("PPI bytes entered inner datagrams")
	}
	for i, child := range children {
		source := packetview.FromCapture(child.Metadata().CaptureInfo).LinkTransformations[0].Sources[0]
		if source.Offset < 16 || !bytes.Equal(wire[source.Offset:source.Offset+source.Length], child.Data()) {
			t.Fatal("source offset lost wrappers", i, source)
		}
	}
}

func TestALPDerivedIPFragmentsKeepAllTransformations(t *testing.T) {
	ip := alpIPv4(40000)
	first := testutil.Fragment(ip, 123, 0, 16, true)
	last := testutil.Fragment(ip, 123, 16, len(ip)-20, false)
	p, f := alpPacket(t, alpConcat(first, last), 1, 100)
	r := &linkReconstructor{}
	children := r.process(p, f, 1)
	if len(children) != 2 {
		t.Fatal(f)
	}
	pipeline := packetview.New(packetview.DefaultLimits())
	if result := pipeline.Process(children[0], 1); result.Packet != nil {
		t.Fatal("partial fragment dispatched")
	}
	result := pipeline.Process(children[1], 1)
	if result.Packet == nil {
		t.Fatal(result.Status)
	}
	ctx := packetview.FromCapture(result.Packet.Metadata().CaptureInfo)
	if len(ctx.LinkTransformations) != 2 || ctx.LinkTransformations[0].ChildOrdinal != 0 || ctx.LinkTransformations[1].ChildOrdinal != 1 {
		t.Fatal("IP reconstruction lost link lineage", ctx)
	}
	pipeline.Reset()
	if pipeline.Stats().BufferedBytes != 0 {
		t.Fatal("derived metadata credits leaked")
	}
}

func TestALPSegmentationIsolationAndFailure(t *testing.T) {
	data := alpIPv4(40000)
	r := &linkReconstructor{}
	ordinal := uint64(0)
	feed := func(seq byte, last bool, sid, plp byte, iface int, payload []byte) []gopacket.Packet {
		ordinal++
		p, f := alpPacket(t, alpSegment(payload, seq, last, sid, plp), iface, 100+int64(ordinal))
		return r.process(p, f, ordinal)
	}
	for _, scope := range [][3]int{{1, 1, 1}, {2, 1, 1}, {1, 2, 1}, {1, 1, 2}} {
		if len(feed(0, false, byte(scope[0]), byte(scope[1]), scope[2], data[:10])) != 0 {
			t.Fatal("early dispatch")
		}
	}
	for _, scope := range [][3]int{{1, 1, 1}, {2, 1, 1}, {1, 2, 1}, {1, 1, 2}} {
		children := feed(1, true, byte(scope[0]), byte(scope[1]), scope[2], data[10:])
		if len(children) != 1 || !bytes.Equal(children[0].Data(), data) {
			t.Fatal("scope leaked", scope)
		}
		ctx := packetview.FromCapture(children[0].Metadata().CaptureInfo)
		if len(ctx.Packets) != 2 || len(ctx.LinkTransformations[0].Sources) != 2 || !ctx.CompletedAt.After(children[0].Metadata().Timestamp) {
			t.Fatal(ctx)
		}
	}
	feed(0, false, 1, 1, 1, data[:10])
	feed(0, false, 1, 1, 1, data[:10])
	if r.health.Incomplete != 1 {
		t.Fatal("new start did not retire previous assembly")
	}
	feed(2, true, 1, 1, 1, data[10:])
	feed(1, true, 1, 1, 1, data[10:])
	if r.health.SequenceErrors != 1 || r.health.MissingStart != 1 {
		t.Fatal(r.health)
	}
	feed(0, false, 1, 1, 1, data[:10])
	r.finish()
	if r.health.BufferedBytes != 0 || len(r.drainEvents()) != 3 {
		t.Fatal("incomplete retirement lost evidence", r.health)
	}
}

func TestALPTSReconstruction(t *testing.T) {
	first := bytes.Repeat([]byte{0xaa}, 188)
	copy(first, []byte{0x47, 0, 0x20, 0x1f})
	second := bytes.Repeat([]byte{0xbb}, 188)
	copy(second, []byte{0x47, 0, 0x20, 0x10})
	wire := append([]byte{0xe5, 0x81}, first[1:]...)
	wire = append(wire, second[4:]...)
	p, f := alpPacket(t, wire, 1, 100)
	r := &linkReconstructor{}
	children := r.process(p, f, 1)
	if len(children) != 3 || !bytes.Equal(children[1].Data(), first) || !bytes.Equal(children[2].Data(), second) {
		t.Fatal(len(children))
	}
	if binary.BigEndian.Uint16(children[0].Data()[1:])&0x1fff != 0x1fff {
		t.Fatal("null PID not restored")
	}
	for _, child := range children {
		if len(packetview.FromCapture(child.Metadata().CaptureInfo).LinkTransformations[0].Synthesized) == 0 {
			t.Fatal("synthetic bytes unqualified")
		}
	}
	if tshark, err := exec.LookPath("tshark"); err == nil {
		path := filepath.Join(t.TempDir(), "alp-ts.pcap")
		if err := os.WriteFile(path, huntPCAP(289, wire), 0600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(tshark, "-n", "-r", path, "-T", "fields", "-e", "mp2t.pid", "-e", "mp2t.cc").Output()
		fields := strings.Split(strings.TrimSpace(string(output)), "\t")
		if err != nil || len(fields) != 2 || fields[1] != "0,15,0" {
			t.Fatalf("independent TS reference disagrees: %v %q", err, output)
		}
		pids := strings.Split(fields[0], ",")
		if len(pids) != 3 {
			t.Fatal("reference lost TS packets", pids)
		}
		for i, want := range []uint64{0x1fff, 0x20, 0x20} {
			got, err := strconv.ParseUint(pids[i], 0, 32)
			if err != nil || got != want {
				t.Fatal("reference PID mismatch", pids)
			}
		}
	}
	wire = []byte{0xe1, 0}
	for range 16 {
		wire = append(wire, first[1:]...)
	}
	p, f = alpPacket(t, wire, 1, 100)
	children = r.process(p, f, 2)
	if len(children) != 144 {
		t.Fatal("maximum declared TS expansion changed", len(children))
	}
}

func TestALPExpiryAndBudgetReadiness(t *testing.T) {
	r := &linkReconstructor{}
	p, f := alpPacket(t, alpSegment([]byte{1}, 0, false, 1, 1), 1, 100)
	r.process(p, f, 1)
	other, _ := alpPacket(t, alpSegment([]byte{1}, 0, false, 2, 1), 1, 131)
	r.advance(other, 2)
	if r.health.Incomplete != 1 || r.health.BufferedBytes != 0 || len(r.drainEvents()) != 1 {
		t.Fatal("capture-time expiry lost pending state", r.health)
	}
	p, f = alpPacket(t, alpSegment([]byte{1}, 0, false, 1, 1), 1, 100)
	p.Metadata().CaptureInfo.AncillaryData = []any{packetview.TimestampMissing(true)}
	r = &linkReconstructor{}
	r.process(p, f, 1)
	r.advance(p, 4098)
	if r.health.BufferedBytes != 0 || r.health.Incomplete != 1 {
		t.Fatal("missing-time ordinal expiry failed", r.health)
	}
	r = &linkReconstructor{}
	r.health.BufferedBytes = linkStateLimit - 1
	p, f = alpPacket(t, alpSegment([]byte{1}, 0, false, 1, 1), 1, 100)
	r.process(p, f, 1)
	if r.err == nil || !r.health.BudgetExceeded || r.health.PeakBytes > linkStateLimit {
		t.Fatal("byte limit failed", r.health)
	}

	var frames [][]byte
	for i := 0; i < 1025; i++ {
		frames = append(frames, alpSegment([]byte{1}, 0, false, byte(i%256), byte(i/256)))
	}
	input := filepath.Join(t.TempDir(), "alp-limit.pcap")
	capture := inputPCAPHeader(binary.LittleEndian, false, 65535, 289)
	for i, frame := range frames {
		capture = append(capture, inputPCAPRecord(binary.LittleEndian, 1700000000, uint32(i), uint32(len(frame)), uint32(len(frame)), frame)...)
	}
	if err := os.WriteFile(input, capture, 0600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	cfg := ultimateCaptureConfig(out, 4, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.IncludeDecoders = "LinkFrame"
	cfg.DecoderConfig.ExcludeDecoders = ""
	err := New(cfg).CollectPcap(input)
	manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	health := bookJSON[linkHealth](t, filepath.Join(out, "LinkReconstructionHealth.json"))
	_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
	if err == nil || manifest.Status != "error" || !os.IsNotExist(readyErr) || !health.BudgetExceeded || health.BufferedBytes != 0 {
		t.Fatal("assembly limit advertised success", err, manifest, health, readyErr)
	}
}

func TestALPSourceDispatchTimeoutCancelsReconstruction(t *testing.T) {
	c := admissionTestCollector(1)
	cancelled := false
	c.runCancel = func() { cancelled = true }
	ip := alpIPv4(40000)
	first, _ := alpPacket(t, alpSegment(ip[:10], 0, false, 1, 1), 1, 100)
	last, _ := alpPacket(t, alpSegment(ip[10:], 1, true, 1, 1), 1, 101)
	if !c.handlePacket(first) {
		t.Fatal("first packet rejected")
	}
	if c.submitPacket(last, true) || !cancelled || c.linkReconstruction.err == nil || c.GetNumPackets() != 1 {
		t.Fatal("unpublished link source did not fail reconstruction")
	}
	<-c.workers[0]
	c.wg.Done()
	c.wg.Wait()
	c.linkReconstruction.finish()
}

func TestALPDerivedCaptureWorkerInvariance(t *testing.T) {
	ip := alpIPv4(40003)
	frames := [][]byte{alpConcat(alpIPv4(40000), alpIPv4(40001), alpIPv4(40002)), alpSegment(ip[:10], 0, false, 1, 1), alpSegment(ip[10:], 1, true, 1, 1)}
	for _, identity := range [][2]byte{{2, 1}, {1, 2}} {
		whole := alpSegment(ip, 0, false, identity[0], identity[1])
		whole[0] = 0x08 | byte(len(ip)>>8&7)
		whole[2] = 7
		frames = append(frames, whole)
	}
	input := filepath.Join(t.TempDir(), "alp.pcap")
	if err := os.WriteFile(input, huntPCAP(289, frames...), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expectedCounts map[string]int
	var expectedDigests map[string]string
	for _, workers := range []int{1, 2, 4, 8} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT=1048576", "NETCAP_AGGREGATE_WORKERS="+strconv.Itoa(workers))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if counts["IPv4"] != 6 || counts["UDP"] != 6 || counts["Connection"] != 6 || counts["LinkFrame"] != 5 {
			t.Fatal(counts)
		}
		manifest := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
		health := bookJSON[linkHealth](t, filepath.Join(out, "LinkReconstructionHealth.json"))
		if manifest.AdmittedPackets != 5 || health.DerivedPackets != 6 || health.Completed != 1 || health.BufferedBytes != 0 {
			t.Fatal(manifest, health)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(expectedCounts, counts) || !reflect.DeepEqual(expectedDigests, digests) {
			t.Fatal(fmt.Sprint(ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests)))
		}
	}
}

func FuzzALPReconstructionBounds(f *testing.F) {
	pack := func(parts ...[]byte) []byte {
		var out []byte
		for _, part := range parts {
			out = binary.LittleEndian.AppendUint16(out, uint16(len(part)))
			out = append(out, part...)
		}
		return out
	}
	ip := alpIPv4(40000)
	f.Add(pack(alpSegment(ip[:10], 0, false, 1, 1), alpSegment(ip[10:], 1, true, 1, 1)))
	f.Add(pack(alpConcat(ip, ip)))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65536 {
			t.Skip()
		}
		r := &linkReconstructor{}
		for ordinal := uint64(1); len(wire) >= 2 && ordinal <= 64; ordinal++ {
			n := int(binary.LittleEndian.Uint16(wire))
			wire = wire[2:]
			if n > len(wire) {
				break
			}
			data := bytes.Clone(wire[:n])
			before := bytes.Clone(data)
			wire = wire[n:]
			p := gopacket.NewPacket(data, captureBusDecoder(289), gopacket.Default)
			p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100, int64(ordinal)), Length: n, CaptureLength: n}
			if frame, ok := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame); ok && frame.ALP != nil {
				children := r.process(p, frame, ordinal)
				if len(children) > 144 {
					t.Fatal("unbounded link fanout")
				}
				for _, child := range children {
					if len(child.Data()) > 65535 {
						t.Fatal("unbounded derived datagram")
					}
				}
			}
			if !bytes.Equal(data, before) || r.health.BufferedBytes > linkStateLimit || len(r.assemblies) > linkAssemblyLimit {
				t.Fatal("link reconstruction escaped bounds")
			}
			r.drainEvents()
		}
		r.finish()
		if r.health.BufferedBytes != 0 {
			t.Fatal("pending reconstruction credits leaked")
		}
	})
}

func TestALPReconstructedTCPReachesHTTP(t *testing.T) {
	request := "GET /alp HTTP/1.1\r\nHost: alp-fixture.test\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	client := testutil.IP(false, false, layers.IPProtocolTCP, testutil.Serialize(&layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 1000, Ack: 2000, ACK: true, PSH: true, Window: 65535}, gopacket.Payload(request)))
	server := testutil.IP(false, true, layers.IPProtocolTCP, testutil.Serialize(&layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 2000, Ack: 1000 + uint32(len(request)), ACK: true, PSH: true, Window: 65535}, gopacket.Payload(response)))
	whole := alpSegment(server, 0, false, 1, 1)
	whole[0] = 0x08 | byte(len(server)>>8&7)
	whole[2] = 7
	frames := [][]byte{alpSegment(client[:10], 0, false, 1, 1), alpSegment(client[10:], 1, true, 1, 1), whole}
	input := filepath.Join(t.TempDir(), "alp-http.pcap")
	if err := os.WriteFile(input, huntPCAP(289, frames...), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expectedCounts map[string]int
	var expectedDigests map[string]string
	for _, workers := range []int{1, 4} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT=1048576", "NETCAP_AGGREGATE_WORKERS="+strconv.Itoa(workers))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if counts["HTTP"] != 1 || counts["Connection"] != 1 || counts["IPv4"] != 2 || counts["TCP"] != 2 {
			t.Fatal("derived packets missed stream dispatch", counts)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(expectedCounts, counts) || !reflect.DeepEqual(expectedDigests, digests) {
			t.Fatal(ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests))
		}
	}
}
