package collector

import (
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/testutil"
)

func TestRecheck168UDPSpillAuditEquivalence(t *testing.T) {
	input := testutil.Recheck168Capture(t, "v168_udp_uniqflows_10k.pcap")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expectedCounts map[string]int
	var expectedDigests map[string]string
	for _, limit := range []int64{0, 32 << 20} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT="+strconv.FormatInt(limit, 10), "NETCAP_AGGREGATE_WORKERS=1")
		start := time.Now()
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("capture: %v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if counts["UDP"] != 10000 || counts["Connection"] != 10000 {
			t.Fatal("supplied flow fixture lost records", counts)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(counts, expectedCounts) || !reflect.DeepEqual(digests, expectedDigests) {
			t.Fatal(ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests))
		}
		t.Logf("aggregate=%d captureSeconds=%.3f records=%v", limit, time.Since(start).Seconds(), counts)
	}
}
