package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

// The Ultimate PCAP carries a wide protocol mix plus IP fragments, oversized
// and malformed frames, tunnels and VLAN stacking, so it exercises paths that
// synthetic fixtures do not reach.
const ultimatePCAP = "../../tests/The Ultimate PCAP v20260316.pcapng"

func ultimatePCAPPath(tb testing.TB) string {
	tb.Helper()
	// Overridable so the digest can be recorded for any real capture.
	path := cmp(os.Getenv("NETCAP_ULTIMATE_PCAP"), ultimatePCAP)
	if _, err := os.Stat(path); err != nil {
		if os.Getenv("NETCAP_REQUIRE_ULTIMATE_PCAP") != "" || os.Getenv("NETCAP_ULTIMATE_PCAP") != "" {
			tb.Fatalf("required Ultimate PCAP %s is not available: %v", path, err)
		}
		tb.Skipf("%s not available (%v)", path, err)
	}
	return path
}

// isPCAPNG detects the container by magic bytes: the corpus contains pcapng
// files named .pcap, so the extension is not reliable.
func isPCAPNG(tb testing.TB, path string) bool {
	tb.Helper()
	f, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		tb.Fatal(err)
	}
	return magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a
}

// ultimateCaptureConfig keeps every decoder on except those whose PostInit
// opens a shared bleve database. Those are single-writer, so any other netcap
// process on the machine makes them fail; a hermetic test cannot depend on them.
func ultimateCaptureConfig(out string, workers, flush int) Config {
	return Config{
		Workers: workers, PacketBufferSize: 100,
		SnapLen: defaults.SnapLen, ReassembleConnections: true,
		NoSignalHandling: true, NoPrompt: true,
		BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Lazy,
		DecoderConfig: &config.Config{
			Out: out, Quiet: true, Proto: true, Buffer: true,
			ExcludeDecoders: "Software,Exploit,Vulnerability",
			MemBufferSize:   defaults.BufferSize, Compression: false,
			SaveConns: false, WaitForConnections: true,
			AllowMissingInit: true, NoOptCheck: true, IgnoreFSMerr: true,
			FlushEvery:          flush,
			ClosePendingTimeOut: 5 * time.Second, CloseInactiveTimeOut: time.Minute,
			StreamBufferSize: 100, StreamDecoderBufSize: 100,
			NumStreamWorkers: 4, BannerSize: 512,
			CalculateEntropy: false, FileStorage: "",
		},
	}
}

// TestUltimatePCAPProcess is the child half of the worker-count comparison.
// Each capture runs in its own process so package-level decoder singletons
// cannot leak between worker counts.
func TestUltimatePCAPProcess(t *testing.T) {
	out := os.Getenv("NETCAP_ULTIMATE_OUT")
	if out == "" {
		return
	}
	workers, err := strconv.Atoi(os.Getenv("NETCAP_ULTIMATE_WORKERS"))
	if err != nil {
		t.Fatal(err)
	}
	flush, err := strconv.Atoi(os.Getenv("NETCAP_ULTIMATE_FLUSH"))
	if err != nil {
		t.Fatal(err)
	}
	input := os.Getenv("NETCAP_ULTIMATE_INPUT")
	c := New(ultimateCaptureConfig(out, workers, flush))
	collect := c.CollectPcap
	if isPCAPNG(t, input) {
		collect = c.CollectPcapNG
	}
	if err := collect(input); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ULTIMATE_PACKETS=%d\n", c.GetNumPackets())
}

func ultimateRun(tb testing.TB, input, out string, workers, flush int) int64 {
	tb.Helper()
	exe, err := os.Executable()
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestUltimatePCAPProcess$", "-test.count=1", "-test.timeout=14m")
	cmd.Env = append(os.Environ(),
		"NETCAP_ULTIMATE_INPUT="+input, "NETCAP_ULTIMATE_OUT="+out,
		fmt.Sprintf("NETCAP_ULTIMATE_WORKERS=%d", workers),
		fmt.Sprintf("NETCAP_ULTIMATE_FLUSH=%d", flush))
	output, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("workers=%d flush=%d: %v\n%s", workers, flush, err, output)
	}
	var packets int64
	for _, line := range strings.Split(string(output), "\n") {
		if n, _ := fmt.Sscanf(line, "ULTIMATE_PACKETS=%d", &packets); n == 1 {
			break
		}
	}
	if packets <= 0 {
		tb.Fatalf("workers=%d: child reported no packets\n%s", workers, output)
	}
	return packets
}

// ultimateRecords digests every audit record file into per-type counts and an
// order-independent content digest, so sharding differences cannot hide behind
// record ordering.
func ultimateRecords(tb testing.TB, out string) (counts map[string]int, digests map[string]string) {
	tb.Helper()
	counts, digests = make(map[string]int), make(map[string]string)
	entries, err := os.ReadDir(out)
	if err != nil {
		tb.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ncap") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".ncap")
		hashes := ultimateRecordHashes(tb, filepath.Join(out, entry.Name()))
		counts[name] = len(hashes)
		// Sort so the digest describes the record set, not the write order.
		sort.Strings(hashes)
		sum := sha256.New()
		for _, h := range hashes {
			sum.Write([]byte(h))
		}
		digests[name] = hex.EncodeToString(sum.Sum(nil))
	}
	if len(counts) == 0 {
		tb.Fatalf("no audit records written to %s", out)
	}
	return counts, digests
}

func ultimateRecordHashes(tb testing.TB, path string) []string {
	tb.Helper()
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		tb.Fatal(err)
	}
	defer r.Close()
	header, err := r.ReadHeader()
	if err != nil {
		tb.Fatalf("%s: %v", path, err)
	}
	record := netio.InitRecord(header.Type)
	msg, ok := record.(proto.Message)
	if !ok {
		tb.Fatalf("%s: record type %v is not a proto message", path, header.Type)
	}
	var hashes []string
	for {
		err := r.Next(msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			tb.Fatalf("%s: %v", path, err)
		}
		data, err := json.Marshal(msg)
		if err != nil {
			tb.Fatalf("%s: marshal %T: %v", path, msg, err)
		}
		hashes = append(hashes, fmt.Sprintf("%x", sha256.Sum256(data)))
	}
	return hashes
}

func ultimateOutputDiff(wantCounts map[string]int, wantDigests map[string]string, gotCounts map[string]int, gotDigests map[string]string) []string {
	var differences []string
	for _, kind := range sortedKeys(wantCounts, gotCounts) {
		if wantCounts[kind] != gotCounts[kind] {
			differences = append(differences, fmt.Sprintf("%s count=%d, want %d", kind, gotCounts[kind], wantCounts[kind]))
			continue
		}
		if wantDigests[kind] != gotDigests[kind] {
			differences = append(differences, fmt.Sprintf("%s content differs", kind))
		}
	}
	return differences
}

func TestUltimateOutputDiff(t *testing.T) {
	tests := []struct {
		name        string
		wantCounts  map[string]int
		wantDigests map[string]string
		gotCounts   map[string]int
		gotDigests  map[string]string
		want        []string
	}{
		{
			name:        "equal",
			wantCounts:  map[string]int{"DNS": 2},
			wantDigests: map[string]string{"DNS": "same"},
			gotCounts:   map[string]int{"DNS": 2},
			gotDigests:  map[string]string{"DNS": "same"},
		},
		{
			name:        "count",
			wantCounts:  map[string]int{"DNS": 2},
			wantDigests: map[string]string{"DNS": "same"},
			gotCounts:   map[string]int{"DNS": 1},
			gotDigests:  map[string]string{"DNS": "same"},
			want:        []string{"DNS count=1, want 2"},
		},
		{
			name:        "content",
			wantCounts:  map[string]int{"DNS": 2},
			wantDigests: map[string]string{"DNS": "a"},
			gotCounts:   map[string]int{"DNS": 2},
			gotDigests:  map[string]string{"DNS": "b"},
			want:        []string{"DNS content differs"},
		},
		{
			name:        "missing type",
			wantCounts:  map[string]int{"DNS": 2},
			wantDigests: map[string]string{"DNS": "a"},
			gotCounts:   map[string]int{},
			gotDigests:  map[string]string{},
			want:        []string{"DNS count=0, want 2"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ultimateOutputDiff(test.wantCounts, test.wantDigests, test.gotCounts, test.gotDigests)
			if !slices.Equal(got, test.want) {
				t.Fatalf("diff = %v, want %v", got, test.want)
			}
		})
	}
}

// TestUltimatePCAPWorkerInvariance is the core guarantee of worker-owned pools:
// flow sharding and per-worker pools must not change what a capture produces.
func TestUltimatePCAPWorkerInvariance(t *testing.T) {
	if testing.Short() {
		t.Skip("processes a 49k packet capture several times")
	}
	input := ultimatePCAPPath(t)

	type result struct {
		counts  map[string]int
		digests map[string]string
		packets int64
	}
	results := make(map[string]result)
	// flush=0 leaves maintenance to shutdown; flush=997 exercises the ordered
	// control messages that now carry maintenance to every worker.
	for _, workers := range []int{1, 2, 4, 8} {
		for _, flush := range []int{0, 997} {
			name := fmt.Sprintf("workers=%d/flush=%d", workers, flush)
			out := t.TempDir()
			packets := ultimateRun(t, input, out, workers, flush)
			counts, digests := ultimateRecords(t, out)
			results[name] = result{counts, digests, packets}
			t.Logf("%s: %d packets, %d audit types", name, packets, len(counts))
		}
	}

	base := results["workers=1/flush=0"]
	// Non-vacuity: a real capture must yield substantial, varied output.
	if base.packets < 40000 {
		t.Fatalf("baseline processed only %d packets", base.packets)
	}
	if len(base.counts) < 20 {
		t.Fatalf("baseline produced only %d audit record types", len(base.counts))
	}
	for _, required := range []string{"Ethernet", "IPv4", "TCP", "UDP", "DNS"} {
		if base.counts[required] == 0 {
			t.Fatalf("baseline produced no %s records", required)
		}
	}

	for _, flush := range []int{0, 997} {
		baseName := fmt.Sprintf("workers=1/flush=%d", flush)
		base = results[baseName]
		for _, workers := range []int{2, 4, 8} {
			name := fmt.Sprintf("workers=%d/flush=%d", workers, flush)
			got := results[name]
			if got.packets != base.packets {
				t.Errorf("%s: processed %d packets, want %d", name, got.packets, base.packets)
			}
			for _, difference := range ultimateOutputDiff(base.counts, base.digests, got.counts, got.digests) {
				t.Errorf("%s differs from %s: %s", name, baseName, difference)
			}
		}
	}
}

// TestUltimatePCAPRepeatability establishes the baseline property the
// invariance test depends on: identical captures must agree exactly.
func TestUltimatePCAPRepeatability(t *testing.T) {
	if testing.Short() {
		t.Skip("processes a 49k packet capture three times")
	}
	input := ultimatePCAPPath(t)
	const workers, flush = 4, 0

	var baselineCounts map[string]int
	var baselineDigests map[string]string
	var baselinePackets int64
	for run := range 3 {
		out := t.TempDir()
		packets := ultimateRun(t, input, out, workers, flush)
		counts, digests := ultimateRecords(t, out)
		if run == 0 {
			baselineCounts, baselineDigests, baselinePackets = counts, digests, packets
			continue
		}
		if packets != baselinePackets {
			t.Errorf("run %d processed %d packets, want %d", run+1, packets, baselinePackets)
		}
		for _, difference := range ultimateOutputDiff(baselineCounts, baselineDigests, counts, digests) {
			t.Errorf("run %d differs from run 1: %s", run+1, difference)
		}
	}
}

// TestUltimatePCAPDigest writes the record digest for one capture so the same
// capture can be compared across git revisions:
//
//	NETCAP_ULTIMATE_DIGEST=/tmp/rev.json go test -run TestUltimatePCAPDigest ./collector
func TestUltimatePCAPDigest(t *testing.T) {
	path := os.Getenv("NETCAP_ULTIMATE_DIGEST")
	if path == "" {
		t.Skip("set NETCAP_ULTIMATE_DIGEST to record a cross-revision digest")
	}
	input := ultimatePCAPPath(t)
	workers, err := strconv.Atoi(cmp(os.Getenv("NETCAP_ULTIMATE_DIGEST_WORKERS"), "4"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	packets := ultimateRun(t, input, out, workers, 0)
	counts, digests := ultimateRecords(t, out)

	lines := []string{fmt.Sprintf("packets\t%d", packets)}
	for _, kind := range sortedKeys(counts) {
		lines = append(lines, fmt.Sprintf("%s\t%d\t%s", kind, counts[kind], digests[kind]))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote digest for %d packets and %d audit types to %s", packets, len(counts), path)
}

func cmp(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func sortedKeys(maps ...map[string]int) []string {
	var keys []string
	for _, m := range maps {
		for k := range m {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// TestUltimatePCAPFragments pins the fragment contract on real fragmented
// traffic: fragments stay visible as network-layer records and never reach
// transport reassembly as partial segments.
func TestUltimatePCAPFragments(t *testing.T) {
	if testing.Short() {
		t.Skip("processes a 49k packet capture")
	}
	input := ultimatePCAPPath(t)
	out := t.TempDir()
	ultimateRun(t, input, out, 4, 0)

	fragments := 0
	for _, spec := range []struct {
		file    string
		isFrag  func(proto.Message) bool
		wantMin int
	}{
		{"IPv4.ncap", func(m proto.Message) bool {
			ip := m.(*types.IPv4)
			return ip.FragOffset > 0 || ip.Flags&1 != 0 // MF is the low flag bit
		}, 1},
		{"IPv6Fragment.ncap", func(proto.Message) bool { return true }, 1},
	} {
		path := filepath.Join(out, spec.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s missing: real fragments produced no records", spec.file)
			continue
		}
		count := ultimateCountRecords(t, path, spec.isFrag)
		if count < spec.wantMin {
			t.Errorf("%s: matched %d fragment records, want at least %d", spec.file, count, spec.wantMin)
		}
		fragments += count
	}
	if fragments == 0 {
		t.Fatal("no fragment records found in a capture known to contain fragments")
	}
	t.Logf("fragment records observed: %d", fragments)
}

func ultimateCountRecords(tb testing.TB, path string, match func(proto.Message) bool) int {
	tb.Helper()
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		tb.Fatal(err)
	}
	defer r.Close()
	header, err := r.ReadHeader()
	if err != nil {
		tb.Fatal(err)
	}
	msg := netio.InitRecord(header.Type).(proto.Message)
	count := 0
	for {
		err := r.Next(msg)
		if err == io.EOF {
			break
		}
		if err != nil {
			tb.Fatal(err)
		}
		if match(msg) {
			count++
		}
	}
	return count
}
