package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestColdControlsPreserveLateHandshakeAndCaptureAudits(t *testing.T) {
	var frames [][]byte
	frame := func(reverse bool, tcp *layers.TCP, payload string) []byte {
		return testutil.Ethernet(testutil.IP(false, reverse, layers.IPProtocolTCP, testutil.Serialize(tcp, gopacket.Payload(payload))))
	}
	for i := range 5000 {
		frames = append(frames, frame(false, &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 80, Seq: uint32(100 + i), SYN: true, Window: 65535}, ""))
	}
	frames = append(frames, frame(true, &layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 500, Ack: 101, SYN: true, ACK: true, Window: 65535}, ""))
	frames = append(frames, frame(false, &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 101, Ack: 501, ACK: true, Window: 65535}, ""))
	request := "GET /late HTTP/1.1\r\nHost: cold-fixture.test\r\n\r\n"
	frames = append(frames, frame(false, &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 101, Ack: 501, ACK: true, PSH: true, Window: 65535}, request))
	frames = append(frames, frame(true, &layers.TCP{SrcPort: 80, DstPort: 40000, Seq: 501, Ack: 101 + uint32(len(request)), ACK: true, PSH: true, Window: 65535}, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	input := filepath.Join(t.TempDir(), "late.pcap")
	if err := os.WriteFile(input, huntPCAP(1, frames...), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expectedCounts map[string]int
	var expectedDigests map[string]string
	for _, mode := range []struct {
		limit   int64
		workers int
	}{{0, 1}, {2048, 1}, {2048, 4}} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT="+strconv.FormatInt(mode.limit, 10), "NETCAP_AGGREGATE_WORKERS="+strconv.Itoa(mode.workers))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cold control capture failed: %v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if counts["HTTP"] != 1 || counts["Connection"] != 5000 {
			t.Fatal("fixture did not exercise late TCP payload", counts)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(counts, expectedCounts) || !reflect.DeepEqual(digests, expectedDigests) {
			t.Fatalf("control spilling changed capture audits: %v", ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests))
		}
	}
}
