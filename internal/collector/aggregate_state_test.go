package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/software"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/identity"
	viewtestutil "github.com/dreadl0ck/netcap/internal/packetview/testutil"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
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
	cfg.DecoderConfig.SaveConns = os.Getenv("NETCAP_AGGREGATE_SAVE_CONNS") == "1"
	if os.Getenv("NETCAP_AGGREGATE_SOFTWARE") == "1" {
		cfg.DecoderConfig.ExcludeDecoders = "Exploit,Vulnerability"
		resolvers.DataBaseFolderPath = t.TempDir()
	}
	c := New(cfg)
	if err = c.CollectPcap(input); err != nil {
		t.Fatal(err)
	}
}

func aggregateSoftwareInput(t *testing.T) string {
	t.Helper()
	input := filepath.Join(t.TempDir(), "software.pcap")
	var frames [][]byte
	seq := [2]uint32{1, 1}
	frame := func(reverse bool, payload string) []byte {
		side, src, dst := 0, layers.TCPPort(50000), layers.TCPPort(80)
		if reverse {
			side, src, dst = 1, dst, src
		}
		tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: seq[side], Ack: seq[1-side], ACK: true, PSH: true, Window: 65535}
		seq[side] += uint32(len(payload))
		return viewtestutil.Ethernet(viewtestutil.IP(false, reverse, layers.IPProtocolTCP, viewtestutil.Serialize(tcp, gopacket.Payload(payload))))
	}
	for i := range 48 {
		frames = append(frames, frame(false, fmt.Sprintf("GET /fixture HTTP/1.1\r\nHost: fixture.test\r\nUser-Agent: Mozilla/5.0 Firefox/%d.0\r\n\r\n", 100+i)))
		frames = append(frames, frame(true, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.1\r\nContent-Length: 0\r\n\r\n"))
	}
	if err := os.WriteFile(input, huntPCAP(1, frames...), 0600); err != nil {
		t.Fatal(err)
	}
	return input
}

func TestAggregateSoftwarePreservesCaptureAuditSets(t *testing.T) {
	input := aggregateSoftwareInput(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expectedCounts map[string]int
	var expectedDigests map[string]string
	for _, mode := range []struct {
		limit   int64
		workers int
	}{{0, 1}, {1, 1}, {2048, 4}} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT="+strconv.FormatInt(mode.limit, 10), "NETCAP_AGGREGATE_WORKERS="+strconv.Itoa(mode.workers), "NETCAP_AGGREGATE_SOFTWARE=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("software capture failed: %v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if counts["HTTP"] != 48 || counts["Software"] != 49 {
			t.Fatal("fixture did not exercise full HTTP/Software pipeline", counts)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests = counts, digests
		} else if !reflect.DeepEqual(counts, expectedCounts) || !reflect.DeepEqual(digests, expectedDigests) {
			t.Fatalf("software spill changed capture audits: %v", ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests))
		}
	}
}

func TestAggregateSoftwareStartsFreshAcrossSequentialCaptures(t *testing.T) {
	input := aggregateSoftwareInput(t)
	oldDB := resolvers.DataBaseFolderPath
	resolvers.DataBaseFolderPath = t.TempDir()
	t.Cleanup(func() { resolvers.DataBaseFolderPath = oldDB })
	for run := range 2 {
		software.Store.Lock()
		software.Store.Items["legacy-fixture"] = &software.AtomicSoftware{Software: &types.Software{Product: "legacy"}}
		software.Store.Unlock()
		cfg := ultimateCaptureConfig(t.TempDir(), 2, 0)
		cfg.DecoderConfig.ExcludeDecoders = "Exploit,Vulnerability"
		cfg.DecoderConfig.MaxAggregateStateBytes = 2048
		c := New(cfg)
		defer c.Stop()
		if err := c.Init(); err != nil {
			t.Fatal(err)
		}
		if software.Store.Size() != 0 || len(software.Store.Items) != 0 {
			t.Fatal("new capture retained old Software state", run)
		}
		if err := c.CollectPcap(input); err != nil {
			t.Fatal(err)
		}
		counts, _ := ultimateRecords(t, cfg.DecoderConfig.Out)
		if counts["Software"] != 49 || software.Store.Size() != 49 {
			t.Fatal("Software state leaked between captures", run, counts["Software"], software.Store.Size())
		}
	}
}

func aggregateNetworkInput(t *testing.T) string {
	t.Helper()
	var frames [][]byte
	for i := range 6 {
		reverse := i%2 == 1
		v4Type := uint8(8)
		v6Type := uint8(128)
		if reverse {
			v4Type, v6Type = 0, 129
		}
		payload := gopacket.Payload(fmt.Sprintf("network-payload-%d", i))
		v4 := viewtestutil.Serialize(&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(v4Type, 0), Id: 7, Seq: uint16(i)}, payload)
		v6 := viewtestutil.Serialize(&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(v6Type, 0)}, &layers.ICMPv6Echo{Identifier: 7, SeqNumber: uint16(i)}, payload)
		frames = append(frames, viewtestutil.Ethernet(viewtestutil.IP(false, reverse, layers.IPProtocolICMPv4, v4)), viewtestutil.Ethernet(viewtestutil.IP(true, reverse, layers.IPProtocolICMPv6, v6)))
	}
	input := filepath.Join(t.TempDir(), "network.pcap")
	if err := os.WriteFile(input, huntPCAP(1, frames...), 0600); err != nil {
		t.Fatal(err)
	}
	return input
}

func TestAggregateNetworkPreservesCaptureAuditSetsAndPayloads(t *testing.T) {
	input := aggregateNetworkInput(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var expectedCounts map[string]int
	var expectedDigests map[string]string
	var expectedFiles map[string]string
	for _, mode := range []struct {
		limit   int64
		workers int
	}{{0, 1}, {1, 1}, {2048, 4}} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT="+strconv.FormatInt(mode.limit, 10), "NETCAP_AGGREGATE_WORKERS="+strconv.Itoa(mode.workers), "NETCAP_AGGREGATE_SAVE_CONNS=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("network capture failed: %v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		paths, err := filepath.Glob(filepath.Join(out, "network", "*", "*.bin"))
		if err != nil || len(paths) != 2 || counts["ICMPv4"] != 6 || counts["ICMPv6"] != 6 {
			t.Fatal("fixture did not exercise both network conversations", paths, counts, err)
		}
		files := map[string]string{}
		for _, path := range paths {
			wire, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			relative, err := filepath.Rel(out, path)
			if err != nil {
				t.Fatal(err)
			}
			files[relative] = string(wire)
		}
		if expectedCounts == nil {
			expectedCounts, expectedDigests, expectedFiles = counts, digests, files
		} else if !reflect.DeepEqual(counts, expectedCounts) || !reflect.DeepEqual(digests, expectedDigests) || !reflect.DeepEqual(files, expectedFiles) {
			t.Fatalf("network spilling changed audits or opaque payloads: %v", ultimateOutputDiff(expectedCounts, expectedDigests, counts, digests))
		}
	}
}

func TestAggregateNetworkOutputFailurePreventsReady(t *testing.T) {
	input := aggregateNetworkInput(t)
	cfg := ultimateCaptureConfig(t.TempDir(), 1, 0)
	cfg.CaptureEvidence = true
	cfg.DecoderConfig.SaveConns = true
	cfg.DecoderConfig.MaxAggregateStateBytes = 1024
	c := New(cfg)
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	if err := os.WriteFile(filepath.Join(cfg.DecoderConfig.Out, "network"), []byte("block directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.CollectPcap(input); err == nil {
		t.Fatal("failed network conversation output reported success")
	}
	if _, err := os.Stat(filepath.Join(cfg.DecoderConfig.Out, "audit-output-ready.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed network output advertised ready audits", err)
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

func TestAggregateUDPReplyFirstAndPayloadEvidence(t *testing.T) {
	input := filepath.Join(t.TempDir(), "udp.pcap")
	reply := viewtestutil.Serialize(&layers.DNS{ID: 7, QR: true})
	query := viewtestutil.Serialize(&layers.DNS{ID: 7})
	frame := func(reverse bool, src, dst layers.UDPPort, payload []byte) []byte {
		return viewtestutil.Ethernet(viewtestutil.IP(false, reverse, layers.IPProtocolUDP, viewtestutil.Serialize(&layers.UDP{SrcPort: src, DstPort: dst}, gopacket.Payload(payload))))
	}
	if err := os.WriteFile(input, huntPCAP(1, frame(true, 137, 53000, reply), frame(false, 53000, 137, query), frame(true, 137, 53000, reply), frame(false, 53000, 137, []byte("<13>fixture log message"))), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var referenceCounts map[string]int
	var referenceDigests map[string]string
	var referencePayload []byte
	var referenceEvidence *utils.StreamEvidenceManifest
	for _, limit := range []int64{0, 2048} {
		out := t.TempDir()
		cmd := exec.Command(exe, "-test.run=^TestAggregateCaptureProcess$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), "NETCAP_AGGREGATE_INPUT="+input, "NETCAP_AGGREGATE_OUT="+out, "NETCAP_AGGREGATE_LIMIT="+strconv.FormatInt(limit, 10), "NETCAP_AGGREGATE_WORKERS=4", "NETCAP_AGGREGATE_SAVE_CONNS=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("capture failed: %v\n%s", err, output)
		}
		counts, digests := ultimateRecords(t, out)
		if counts["Syslog"] == 0 {
			t.Fatal("fixture did not exercise the UDP stream decoder")
		}
		paths, _ := filepath.Glob(filepath.Join(out, "udp", "*", "*.bin"))
		if len(paths) != 1 {
			t.Fatal(paths)
		}
		payload, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		paths, _ = filepath.Glob(filepath.Join(out, "stream-evidence", "stream-*", "manifest.json"))
		if len(paths) != 1 {
			t.Fatal(paths)
		}
		wire, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var evidence utils.StreamEvidenceManifest
		if err = json.Unmarshal(wire, &evidence); err != nil {
			t.Fatal(err)
		}
		if len(evidence.Spans) != 4 {
			t.Fatal("UDP spans lost", evidence)
		}
		if limit == 0 {
			referenceCounts, referenceDigests = counts, digests
			referencePayload, referenceEvidence = payload, &evidence
		} else if !reflect.DeepEqual(referenceCounts, counts) || !reflect.DeepEqual(referenceDigests, digests) || !bytes.Equal(referencePayload, payload) || !reflect.DeepEqual(*referenceEvidence, evidence) {
			t.Fatal("stored UDP changed audits, payload bytes or evidence")
		}
	}
}
