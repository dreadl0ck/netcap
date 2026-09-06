package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// The Ultimate PCAP carries a wide protocol mix plus IP fragments, oversized
// and malformed frames, tunnels and VLAN stacking, so it exercises paths that
// synthetic fixtures do not reach.
const ultimatePCAP = "../tests/The Ultimate PCAP v20260316.pcapng"

func ultimatePCAPPath(tb testing.TB) string {
	tb.Helper()
	// Overridable so the digest can be recorded for any real capture.
	path := cmp(os.Getenv("NETCAP_ULTIMATE_PCAP"), ultimatePCAP)
	if _, err := os.Stat(path); err != nil {
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
		// Text form rather than wire bytes: stable across map iteration order.
		hashes = append(hashes, fmt.Sprintf("%x", sha256.Sum256([]byte(msg.String()))))
	}
	return hashes
}

// ultimateOrderDependent are audit types whose content depends on processing
// order rather than on the packets. Capturing this file on master (e33ac5f7) at
// 1, 2, 4 and 8 workers already yields a different digest for the first eleven.
//
// The underlying cause is decoders that merge distinct flows under a colliding
// key, so which flow supplies the metadata depends on who runs first:
// udp_stream.go keys streams by the transport flow alone, ignoring addresses,
// so two syslog senders sharing a source port become one stream. Any change to
// dispatch order therefore moves these records around; that is a property of
// those decoders, not of pool ownership. Everything else must match exactly.
var ultimateOrderDependent = map[string]bool{
	"DeviceProfile": true, "Host": true, "Kerberos": true, "MQTTSN": true,
	"Mail": true, "Protobuf": true, "SIP": true, "SMB": true, "SMTP": true,
	"Service": true, "TLSCertificate": true, "Syslog": true,
}

// TestUltimatePCAPWorkerInvariance is the core guarantee of worker-owned pools:
// flow sharding and per-worker pools must not change what a capture produces.
// Beyond the known set above, the baseline is captured twice so any decoder
// that disagrees with itself is also excluded rather than blamed on sharding.
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

	// Calibrate: a second identical baseline capture exposes the decoders that
	// are nondeterministic regardless of worker count.
	baseName := "workers=1/flush=0"
	base := results[baseName]
	calibOut := t.TempDir()
	ultimateRun(t, input, calibOut, 1, 0)
	calibCounts, calibDigests := ultimateRecords(t, calibOut)

	unstable := make(map[string]bool)
	for kind := range ultimateOrderDependent {
		unstable[kind] = true
	}
	for _, kind := range sortedKeys(base.counts, calibCounts) {
		if base.counts[kind] != calibCounts[kind] || base.digests[kind] != calibDigests[kind] {
			unstable[kind] = true
		}
	}
	stable := len(base.counts) - len(unstable)
	t.Logf("comparing %d of %d audit types exactly; excluded as order dependent: %v",
		stable, len(base.counts), sortedKeys(toCountMap(unstable)))
	// Guard against the comparison quietly becoming meaningless.
	if stable < 60 {
		t.Fatalf("only %d audit types are reproducible; comparison is too weak", stable)
	}
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

	for name, got := range results {
		if name == baseName {
			continue
		}
		if got.packets != base.packets {
			t.Errorf("%s: processed %d packets, want %d", name, got.packets, base.packets)
		}
		for _, kind := range sortedKeys(base.counts, got.counts) {
			if unstable[kind] {
				// Only require that the decoder still produces output at all.
				if (base.counts[kind] == 0) != (got.counts[kind] == 0) {
					t.Errorf("%s: %s records = %d, baseline %d",
						name, kind, got.counts[kind], base.counts[kind])
				}
				continue
			}
			if base.counts[kind] != got.counts[kind] {
				t.Errorf("%s: %s records = %d, want %d",
					name, kind, got.counts[kind], base.counts[kind])
				continue
			}
			if base.digests[kind] != got.digests[kind] {
				t.Errorf("%s: %s record content differs from %s", name, kind, baseName)
			}
		}
	}
}

// TestUltimatePCAPRepeatability establishes the baseline property the
// invariance test depends on: whether two identical captures agree at all.
func TestUltimatePCAPRepeatability(t *testing.T) {
	if testing.Short() {
		t.Skip("processes a 49k packet capture twice")
	}
	input := ultimatePCAPPath(t)
	const workers, flush = 4, 0

	outA, outB := t.TempDir(), t.TempDir()
	if a, b := ultimateRun(t, input, outA, workers, flush), ultimateRun(t, input, outB, workers, flush); a != b {
		t.Fatalf("packet counts differ between identical runs: %d vs %d", a, b)
	}
	countsA, digestsA := ultimateRecords(t, outA)
	countsB, digestsB := ultimateRecords(t, outB)

	var unstable []string
	for _, kind := range sortedKeys(countsA, countsB) {
		if countsA[kind] != countsB[kind] || digestsA[kind] != digestsB[kind] {
			unstable = append(unstable, fmt.Sprintf("%s(%d vs %d)", kind, countsA[kind], countsB[kind]))
		}
	}
	if len(unstable) > 0 {
		t.Logf("record types that differ between two identical captures: %s", strings.Join(unstable, " "))
		t.Logf("%d of %d audit types are not reproducible run to run", len(unstable), len(countsA))
	} else {
		t.Log("identical captures produced identical output")
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

func toCountMap(set map[string]bool) map[string]int {
	out := make(map[string]int, len(set))
	for k := range set {
		out[k] = 1
	}
	return out
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
