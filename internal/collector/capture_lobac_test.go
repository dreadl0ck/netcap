package collector

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/linkaudit"
	"github.com/dreadl0ck/netcap/internal/lowpan"
	"github.com/dreadl0ck/netcap/internal/packetview"
	"github.com/gopacket/gopacket"
)

func encodeMSTPCOBSTest(data []byte) []byte {
	out := []byte{0}
	code, index := byte(1), 0
	for _, value := range data {
		if value == 0 {
			out[index] = code
			index = len(out)
			out = append(out, 0)
			code = 1
			continue
		}
		out = append(out, value)
		code++
		if code == 255 {
			out[index] = code
			index = len(out)
			out = append(out, 0)
			code = 1
		}
	}
	out[index] = code
	for i := range out {
		out[i] ^= 0x55
	}
	return out
}

func lobacTestFrame(data []byte) []byte {
	encoded := encodeMSTPCOBSTest(data)
	crc := encodeMSTPCOBSTest(binary.LittleEndian.AppendUint32(nil, mstpCRC32K(encoded)))
	n := len(encoded) + len(crc) - 2
	header := []byte{0x55, 0xff, 34, 255, 1, byte(n >> 8), byte(n), 0}
	header[7] = mstpHeaderCRC(header[2:7])
	return append(append(header, encoded...), crc...)
}

func TestLoBACContextLearningAndRFC8163IPv6(t *testing.T) {
	r := &linkReconstructor{}
	src := netip.MustParseAddr("fe80::ff:fe00:1").As16()
	dst := netip.MustParseAddr("ff02::1").As16()
	ra := make([]byte, 32)
	ra[0] = 134
	copy(ra[16:], []byte{34, 2, 64, 0x10, 0, 0, 0, 5, 0xaa, 0xaa})
	binary.BigEndian.PutUint16(ra[2:], lowpan.Checksum(src, dst, 58, ra))
	compressed := []byte{0x7b, 8, 58}
	compressed = append(compressed, src[:]...)
	compressed = append(compressed, dst[:]...)
	compressed = append(compressed, ra...)
	feed := func(wire []byte, iface int, stamp int64, ordinal uint64) ([]gopacket.Packet, *linkaudit.LinkFrame) {
		p := gopacket.NewPacket(wire, captureBusDecoder(165), gopacket.Default)
		p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(stamp, 0), InterfaceIndex: iface, Length: len(wire), CaptureLength: len(wire)}
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer())
		}
		f := p.Layer(linkaudit.LayerLinkFrame).(*linkaudit.LinkFrame)
		r.advance(p, ordinal)
		return r.processLoBAC(p, f, ordinal), f
	}
	children, _ := feed(lobacTestFrame(compressed), 1, 100, 1)
	if len(children) != 1 || len(r.lobacContexts) != 1 {
		t.Fatal("RA context was not learned", r.lobacContexts)
	}
	wire, err := hex.DecodeString(strings.Join(strings.Fields(mstpRFC8163), ""))
	if err != nil {
		t.Fatal(err)
	}
	children, f := feed(wire, 1, 101, 2)
	if len(children) != 1 || f.PayloadProtocol != "IPv6" || len(children[0].Data()) != 558 {
		t.Fatal(f, len(children))
	}
	ip := children[0].Data()
	copy(src[:], ip[8:24])
	copy(dst[:], ip[24:40])
	if netip.AddrFrom16(src).String() != "aaaa::1" || netip.AddrFrom16(dst).String() != "aaaa::ff:fe00:1" || lowpan.Checksum(src, dst, 58, ip[40:]) != 0 {
		t.Fatal("published IPv6 bytes/checksum changed")
	}
	ctx := packetview.FromCapture(children[0].Metadata().CaptureInfo)
	if len(ctx.Packets) != 1 || len(ctx.LinkTransformations[0].Sources) != 3 || ctx.LinkTransformations[0].Sources[2].Purpose != "compression-context" {
		t.Fatal("context provenance lost", ctx)
	}
	children, _ = feed(wire, 2, 102, 3)
	if len(children) != 0 {
		t.Fatal("context crossed physical interfaces")
	}
	children, _ = feed(wire, 1, 99, 4)
	if len(children) != 0 {
		t.Fatal("future context applied to late packet")
	}
	children, _ = feed(wire, 1, 401, 5)
	if len(children) != 0 {
		t.Fatal("expired context applied")
	}
	r.finish()
	if r.health.BufferedBytes != 0 {
		t.Fatal("context credits leaked", r.health)
	}

	r = &linkReconstructor{}
	bad := bytes.Clone(ra)
	bad[2] ^= 1
	packet := make([]byte, 40+len(bad))
	packet[0], packet[6], packet[7] = 0x60, 58, 255
	copy(packet[8:], netip.MustParseAddr("fe80::1").AsSlice())
	copy(packet[24:], netip.MustParseAddr("ff02::1").AsSlice())
	copy(packet[40:], bad)
	f = busFrame(165, "MS/TP")
	r.learnLoBACContexts("if:1/mstp", packet, gopacket.CaptureInfo{Timestamp: time.Unix(100, 0)}, 1, f)
	if len(r.lobacContexts) != 0 {
		t.Fatal("invalid RA checksum installed context")
	}
}

func TestLoBACCaptureWorkerInvariance(t *testing.T) {
	src := netip.MustParseAddr("fe80::ff:fe00:1").As16()
	dst := netip.MustParseAddr("ff02::1").As16()
	ra := make([]byte, 32)
	ra[0] = 134
	copy(ra[16:], []byte{34, 2, 64, 0x10, 0, 0, 0, 5, 0xaa, 0xaa})
	binary.BigEndian.PutUint16(ra[2:], lowpan.Checksum(src, dst, 58, ra))
	compressed := []byte{0x7b, 8, 58}
	compressed = append(compressed, src[:]...)
	compressed = append(compressed, dst[:]...)
	compressed = append(compressed, ra...)
	wire, err := hex.DecodeString(strings.Join(strings.Fields(mstpRFC8163), ""))
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "lobac.pcap")
	if err := os.WriteFile(input, huntPCAP(165, lobacTestFrame(compressed), wire), 0600); err != nil {
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
		if counts["IPv6"] != 2 || counts["ICMPv6"] != 2 || counts["LinkFrame"] != 2 {
			t.Fatal(counts)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(expectedCounts, counts) || !reflect.DeepEqual(expectedDigests, digests) {
			t.Fatal(ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests))
		}
	}
}
