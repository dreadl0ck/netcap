package collector

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/identity"
	"github.com/gopacket/gopacket/layers"
)

func TestAggregateCaptureProcess(t *testing.T) {
	input := os.Getenv("NETCAP_AGGREGATE_INPUT")
	if input == "" {
		return
	}
	limit, err := strconv.ParseInt(os.Getenv("NETCAP_AGGREGATE_LIMIT"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := strconv.Atoi(os.Getenv("NETCAP_AGGREGATE_WORKERS"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := ultimateCaptureConfig(os.Getenv("NETCAP_AGGREGATE_OUT"), workers, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.MaxAggregateStateBytes = limit
	c := New(cfg)
	if err = c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
}

func TestAggregateSpillingPreservesCaptureAuditSets(t *testing.T) {
	input := filepath.Join(t.TempDir(), "udp.pcap")
	writeUniqueUDPFlows(t, input, 1500)
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
			t.Fatalf("limit=%d workers=%d: %v\n%s", mode.limit, mode.workers, err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(counts, expectedCounts) || !reflect.DeepEqual(digests, expectedDigests) {
			t.Fatalf("disk-backed audit set differs: limit=%d workers=%d\ncounts=%v expected=%v\ndigests=%v expected=%v", mode.limit, mode.workers, counts, expectedCounts, digests, expectedDigests)
		}
		var manifest evidence.CaptureManifest
		readInputJSON(t, filepath.Join(out, "capture-manifest.json"), &manifest)
		if manifest.Config.MaxAggregateStateBytes != mode.limit {
			t.Fatal("manifest omitted effective aggregate cache", manifest.Config)
		}
		if mode.limit > 0 {
			var health aggregate.Health
			readInputJSON(t, filepath.Join(out, "AggregateStateHealth.json"), &health)
			if health.PeakBytes > mode.limit || health.Evictions == 0 || health.DiskWrites == 0 {
				t.Fatal("spilling not exercised", health)
			}
		}
		if files, err := filepath.Glob(filepath.Join(out, ".netcap-aggregate-*")); err != nil || len(files) > 0 {
			t.Fatal("aggregate scratch remained after capture", files, err)
		}
	}
	if expectedCounts["Connection"] != 1500 {
		t.Fatal("scale fixture lost conversations", expectedCounts)
	}
}

func TestAggregateFailureCancelsAndFailsCapture(t *testing.T) {
	input := filepath.Join(t.TempDir(), "udp.pcap")
	writeUniqueUDPFlows(t, input, 10)
	cfg := ultimateCaptureConfig(t.TempDir(), 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.MaxAggregateStateBytes = 1024
	c := New(cfg)
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	injected := errors.New("injected aggregate I/O failure")
	if err := c.config.DecoderConfig.AggregateStore.Do(func(*aggregate.Tx) error { return injected }); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if err := c.CollectPcap(input); err == nil {
		t.Fatal("capture succeeded after aggregate storage failure")
	}
	c.Stop()
	if !errors.Is(c.captureEvidenceError, injected) {
		t.Fatal("capture lost aggregate failure", c.captureEvidenceError)
	}
	if _, err := os.Stat(filepath.Join(cfg.DecoderConfig.Out, "audit-output-ready.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed capture advertised ready audit output", err)
	}
}

func TestAggregateSpillingPreservesIdentitySeeding(t *testing.T) {
	input := filepath.Join(t.TempDir(), "identity.pcap")
	start := time.Unix(1700000000, 0)
	dhcp := replayDHCP(start, 5)
	d := dhcp.stack[len(dhcp.stack)-1].(*layers.DHCPv4)
	d.Options = append(d.Options, layers.DHCPOption{Type: layers.DHCPOptHostname, Length: 12, Data: []byte("fixture-host")})
	writeBehaviorPCAP(t, input, []behaviorPacket{dhcp, replayARP(start.Add(time.Second), "192.0.2.130", 5), replayNDP(start.Add(2*time.Second), 5), replaySYN(start.Add(3*time.Second), "192.0.2.130", "192.0.2.10", 80, 1)})
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expected *identity.Report
	for _, mode := range []struct {
		limit   int64
		workers int
	}{{0, 1}, {2048, 1}, {2048, 4}} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT="+strconv.FormatInt(mode.limit, 10), "NETCAP_AGGREGATE_WORKERS="+strconv.Itoa(mode.workers))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("capture failed: %v\n%s", err, output)
		}
		var report identity.Report
		readInputJSON(t, filepath.Join(out, identity.Filename), &report)
		if expected == nil {
			expected = &report
		} else if !reflect.DeepEqual(report, *expected) {
			t.Fatalf("identity changed with limit=%d workers=%d\ngot: %+v\nwant: %+v", mode.limit, mode.workers, report, *expected)
		}
		found := false
		for _, host := range report.Hosts {
			if host.IP == "192.0.2.130" && (host.Hostname == "fixture-host" || slices.Contains(host.HostnameAliases, "fixture-host")) {
				found = true
			}
		}
		if !found {
			t.Fatalf("identity fixture produced no bound hostname: %+v", report.Hosts)
		}
	}
}
