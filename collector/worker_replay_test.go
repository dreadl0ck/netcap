package collector

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap/decoder/config"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

const workerReplayFlows = 48
const workerReplayPackets = workerReplayFlows*12 + workerReplayFlows/3*5

type workerReplayConversation struct{ Client, Server string }

func workerReplayMessages(i, segments int) workerReplayConversation {
	body := fmt.Sprintf("response-%03d:%s", i, strings.Repeat("abcdefgh", 64*segments))
	return workerReplayConversation{
		Client: fmt.Sprintf("GET /replay/%03d HTTP/1.1\r\nHost: replay.invalid\r\nX-Flow: %03d\r\n\r\n", i, i),
		Server: fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body),
	}
}

// Round-robin stages keep all flows active together. Both directions contain
// reordering and retransmission; closure rotates FIN, RST, and EOF-open.
func workerReplayPCAP(tb testing.TB, path string, segments int) (packets int, wireBytes int64) {
	tb.Helper()
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	shards := [8]int{}
	sharder := &Collector{numWorkers: len(shards)}
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		tb.Fatal(err)
	}
	messages := make([]workerReplayConversation, workerReplayFlows)
	for i := range messages {
		messages[i] = workerReplayMessages(i, segments)
	}
	for step := range 16 + segments - 1 {
		stage := step
		if step >= 9 {
			stage = 9 + max(0, step-9-(segments-1))
		}
		for i := range workerReplayFlows {
			msg := messages[i]
			clientSeq, serverSeq := uint32(1001+i*10000), uint32(5001+i*10000)
			tcp := &layers.TCP{SrcPort: layers.TCPPort(20000 + i), DstPort: 80, Seq: clientSeq, Ack: serverSeq, ACK: true, Window: 65535}
			reverse := false
			var payload string
			switch stage {
			case 0:
				tcp.SYN, tcp.ACK, tcp.Seq, tcp.Ack = true, false, clientSeq-1, 0
			case 1:
				reverse = true
				tcp.SYN, tcp.Seq, tcp.Ack = true, serverSeq-1, clientSeq
			case 2:
			case 3, 4, 5, 6:
				start, end := 0, 24
				if stage == 4 {
					start, end = 48, len(msg.Client)
				}
				if stage == 5 {
					start, end = 24, 48
				}
				tcp.Seq += uint32(start)
				payload = msg.Client[start:end]
			case 7:
				reverse = true
				tcp.Seq, tcp.Ack = serverSeq, clientSeq+uint32(len(msg.Client))
			case 8, 9, 10, 11:
				reverse = true
				start, end := 0, 32
				if stage == 9 {
					start, end = 64, len(msg.Server)
					if segments > 1 {
						// Long responses are in order, with a duplicate at stage 10.
						start = 32 + (step-9)*512
						end = min(start+512, len(msg.Server))
						if step == 9+segments-1 {
							end = len(msg.Server)
						}
					}
				}
				if stage == 10 {
					start, end = 32, 64
				}
				tcp.Seq, tcp.Ack = serverSeq+uint32(start), clientSeq+uint32(len(msg.Client))
				payload = msg.Server[start:end]
			default:
				if i%3 == 2 || (i%3 == 1 && stage > 12) {
					continue
				}
				tcp.Seq, tcp.Ack = clientSeq+uint32(len(msg.Client)), serverSeq+uint32(len(msg.Server))
				if i%3 == 1 {
					tcp.RST = true
				} else {
					tcp.FIN = stage == 12 || stage == 14
					if stage == 13 || stage == 14 {
						reverse = true
						tcp.Seq, tcp.Ack = tcp.Ack, tcp.Seq+1
					}
					if stage == 15 {
						tcp.Seq++
						tcp.Ack++
					}
				}
			}
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.IPv4(192, 0, 2, byte(i/8+1)), DstIP: net.IPv4(198, 51, 100, 1)}
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			if reverse {
				ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
				tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
				eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
			}
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
				tb.Fatal(err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
				tb.Fatal(err)
			}
			data := buf.Bytes()
			if stage == 0 {
				shards[sharder.getSymmetricWorkerIndex(gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default))]++
			}
			spacing := time.Microsecond
			if segments == 1 {
				spacing = time.Millisecond
			}
			ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, 0).Add(time.Duration(packets) * spacing), CaptureLength: len(data), Length: len(data)}
			if err := w.WritePacket(ci, data); err != nil {
				tb.Fatal(err)
			}
			packets++
			wireBytes += int64(len(data))
		}
	}
	if err := f.Close(); err != nil {
		tb.Fatal(err)
	}
	for shard, flows := range shards {
		if flows == 0 {
			tb.Fatalf("fixture leaves shard %d idle: %v", shard, shards)
		}
	}
	if want := workerReplayPackets + workerReplayFlows*(segments-1); packets != want {
		tb.Fatalf("fixture packets = %d, want %d", packets, want)
	}
	return packets, wireBytes
}

// Fresh processes isolate decoder writers, resolver initialization, and stream
// reader singletons from other collector tests. No external fixture or DB loads.
func TestWorkerReplayProcess(t *testing.T) {
	input := os.Getenv("NETCAP_WORKER_REPLAY_INPUT")
	if input == "" {
		return
	}
	workers, err := strconv.Atoi(os.Getenv("NETCAP_WORKER_REPLAY_WORKERS"))
	if err != nil {
		t.Fatal(err)
	}
	flush, err := strconv.Atoi(os.Getenv("NETCAP_WORKER_REPLAY_FLUSH"))
	if err != nil {
		t.Fatal(err)
	}
	segments, err := strconv.Atoi(os.Getenv("NETCAP_WORKER_REPLAY_SEGMENTS"))
	if err != nil || segments < 1 {
		t.Fatal("invalid response segment count")
	}
	c := New(Config{
		Workers: workers, PacketBufferSize: 8, ReassembleConnections: true,
		NoSignalHandling: true, NoPrompt: true,
		BaseLayer: layers.LayerTypeEthernet, DecodeOptions: gopacket.Default,
		DecoderConfig: &config.Config{
			Out: os.Getenv("NETCAP_WORKER_REPLAY_OUT"), Quiet: true,
			IncludeDecoders: "HTTP", Proto: true, Buffer: true, MemBufferSize: 4096,
			SaveConns: true, WaitForConnections: true, NoOptCheck: true,
			FlushEvery: flush, ClosePendingTimeOut: 5 * time.Second, CloseInactiveTimeOut: time.Minute,
			StreamBufferSize: 8, StreamDecoderBufSize: 8, NumStreamWorkers: 4, BannerSize: 256,
		},
	})
	wantPackets := workerReplayPackets + workerReplayFlows*(segments-1)
	if segments == 1 {
		if err := c.CollectPcap(input); err != nil {
			t.Fatal(err)
		}
	} else {
		r, f, err := OpenPCAP(input)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := c.handleLinkType(r.LinkType()); err != nil {
			t.Fatal(err)
		}
		initStart := time.Now()
		if err := c.Init(); err != nil {
			t.Fatal(err)
		}
		initElapsed := time.Since(initStart)
		c.numPackets = int64(wantPackets)
		start := time.Now()
		for {
			data, ci, err := r.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			atomic.AddInt64(&c.current, 1)
			// Feed real workers identically on both revisions. Admission's
			// WaitGroup ownership changed; the end-to-end test covers that API.
			p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			p.Metadata().CaptureInfo = ci
			c.wg.Add(1)
			c.workers[c.getSymmetricWorkerIndex(p)] <- p
		}
		c.wg.Wait()
		elapsed := time.Since(start)
		if got := c.allProtosAtomic.Snapshot()["TCP"]; got != int64(wantPackets) {
			t.Fatalf("worker TCP count = %d, want %d", got, wantPackets)
		}
		cleanupStart := time.Now()
		c.cleanup(false)
		fmt.Printf("WORKER_INIT_NS=%d\nWORKER_PROCESSING_NS=%d\nWORKER_CLEANUP_NS=%d\n",
			initElapsed.Nanoseconds(), elapsed.Nanoseconds(), time.Since(cleanupStart).Nanoseconds())
	}
	if got := c.GetNumPackets(); got != int64(wantPackets) {
		t.Fatalf("processed packets = %d, want %d", got, wantPackets)
	}
}

// workerReplayPhases holds the child's self-reported in-process phase timings.
type workerReplayPhases struct{ Init, Processing, Cleanup time.Duration }

func workerReplayRun(tb testing.TB, input, out string, workers, flush, segments int) workerReplayPhases {
	tb.Helper()
	exe, err := os.Executable()
	if err != nil {
		tb.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWorkerReplayProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "NETCAP_WORKER_REPLAY_INPUT="+input, "NETCAP_WORKER_REPLAY_OUT="+out,
		fmt.Sprintf("NETCAP_WORKER_REPLAY_WORKERS=%d", workers), fmt.Sprintf("NETCAP_WORKER_REPLAY_FLUSH=%d", flush),
		fmt.Sprintf("NETCAP_WORKER_REPLAY_SEGMENTS=%d", segments))
	output, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("replay: %v\n%s", err, output)
	}
	if segments > 1 {
		var phases workerReplayPhases
		for _, line := range strings.Split(string(output), "\n") {
			var ns int64
			switch {
			case mustScan(line, "WORKER_INIT_NS=%d", &ns):
				phases.Init = time.Duration(ns)
			case mustScan(line, "WORKER_PROCESSING_NS=%d", &ns):
				phases.Processing = time.Duration(ns)
			case mustScan(line, "WORKER_CLEANUP_NS=%d", &ns):
				phases.Cleanup = time.Duration(ns)
			}
		}
		if phases.Processing <= 0 {
			tb.Fatalf("missing processing measurement: %s", output)
		}
		return phases
	}
	return workerReplayPhases{}
}

func mustScan(line, format string, ns *int64) bool {
	n, _ := fmt.Sscanf(line, format, ns)
	return n == 1 && *ns > 0
}

func workerReplayVerify(tb testing.TB, out string, segments int) {
	tb.Helper()
	want := make(map[workerReplayConversation]int)
	for i := range workerReplayFlows {
		want[workerReplayMessages(i, segments)]++
	}
	got := make(map[workerReplayConversation]int)
	err := filepath.WalkDir(filepath.Join(out, "tcp"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".bin") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var client, server strings.Builder
		for s := string(data); s != ""; {
			var dst *strings.Builder
			switch {
			case strings.HasPrefix(s, ansi.Red):
				dst = &client
				s = strings.TrimPrefix(s, ansi.Red)
			case strings.HasPrefix(s, ansi.Blue):
				dst = &server
				s = strings.TrimPrefix(s, ansi.Blue)
			default:
				return fmt.Errorf("unexpected conversation framing in %s: %q", path, s)
			}
			chunk, rest, ok := strings.Cut(s, ansi.Reset)
			if !ok {
				return fmt.Errorf("missing color reset in %s", path)
			}
			dst.WriteString(chunk)
			s = rest
		}
		got[workerReplayConversation{Client: client.String(), Server: server.String()}]++
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		for msg, count := range want {
			if got[msg] != count {
				tb.Errorf("conversation %q: got %d, want %d", msg.Client, got[msg], count)
			}
		}
		for msg, count := range got {
			if want[msg] != count {
				tb.Errorf("unexpected conversation (%d copies): %#v", count, msg)
			}
		}
		tb.Fatal("conversation multiset mismatch")
	}
	r, err := netio.Open(filepath.Join(out, "HTTP.ncap"), 4096)
	if err != nil {
		tb.Fatal(err)
	}
	defer r.Close()
	header, err := r.ReadHeader()
	if err != nil {
		tb.Fatal(err)
	}
	if header.Type != types.Type_NC_HTTP {
		tb.Fatalf("unexpected header: %v", header.Type)
	}
	count := 0
	urls := make(map[string]int)
	for {
		record := new(types.HTTP)
		err := r.Next(record)
		if err == io.EOF {
			break
		}
		if err != nil {
			tb.Fatal(err)
		}
		count++
		urls[record.URL]++
		i, err := strconv.Atoi(strings.TrimPrefix(record.URL, "/replay/"))
		if err != nil || i < 0 || i >= workerReplayFlows {
			tb.Fatalf("unexpected HTTP URL: %q", record.URL)
		}
		_, body, _ := strings.Cut(workerReplayMessages(i, segments).Server, "\r\n\r\n")
		if record.Method != "GET" || record.Host != "replay.invalid" || record.StatusCode != 200 ||
			record.ResContentLength != int32(len(body)) || record.SrcIP != fmt.Sprintf("192.0.2.%d", i/8+1) ||
			record.DstIP != "198.51.100.1" || record.SrcPort != int32(20000+i) || record.DstPort != 80 {
			tb.Fatalf("unexpected HTTP semantics: %s", record)
		}
	}
	if count != workerReplayFlows {
		tb.Fatalf("HTTP records = %d, want %d", count, workerReplayFlows)
	}
	for i := range workerReplayFlows {
		url := fmt.Sprintf("/replay/%03d", i)
		if urls[url] != 1 {
			tb.Errorf("HTTP records for %s = %d, want 1", url, urls[url])
		}
	}
}

func TestWorkerReplay(t *testing.T) {
	input := filepath.Join(t.TempDir(), "replay.pcap")
	packets, wireBytes := workerReplayPCAP(t, input, 1)
	t.Logf("%d flows, %d packets, %d wire bytes", workerReplayFlows, packets, wireBytes)
	for _, workers := range []int{1, 2, 4, 8} {
		for _, flush := range []int{0, 7} {
			t.Run(fmt.Sprintf("workers=%d/flush=%d", workers, flush), func(t *testing.T) {
				out := t.TempDir()
				workerReplayRun(t, input, out, workers, flush, 1)
				workerReplayVerify(t, out, 1)
			})
		}
	}
}

// Includes process startup, collector initialization, PCAP ingestion, reassembly,
// HTTP decoding, persisted output, and shutdown. Fixture creation and output
// verification are excluded. Allocation metrics would measure only the parent.
func BenchmarkWorkerReplay(b *testing.B) {
	input := filepath.Join(b.TempDir(), "replay.pcap")
	packets, wireBytes := workerReplayPCAP(b, input, 1)
	for _, workers := range []int{1, 4, 8} {
		for _, flush := range []int{0, 7} {
			b.Run(fmt.Sprintf("workers=%d/flush=%d", workers, flush), func(b *testing.B) {
				out := b.TempDir()
				b.SetBytes(wireBytes)
				b.ResetTimer()
				for range b.N {
					workerReplayRun(b, input, out, workers, flush, 1)
					b.StopTimer()
					workerReplayVerify(b, out, 1)
					if err := os.RemoveAll(out); err != nil {
						b.Fatal(err)
					}
					if err := os.Mkdir(out, 0700); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
				b.StopTimer()
				b.ReportMetric(float64(packets), "packets/op")
				b.ReportMetric(float64(wireBytes), "wire-bytes/op")
				b.ReportMetric(float64(packets*b.N)/b.Elapsed().Seconds(), "packets/s")
			})
		}
	}
}

// ns/op covers the full child lifecycle including process startup. The child
// reports three in-process phases: init-ns/op (Collector.Init), processing-ns/op
// (PCAP reads, dispatch, real TCP factory callbacks, worker drain) and
// cleanup-ns/op (flush, reader join, teardown; baseline also burns fixed
// reassembly timeouts here). Async HTTP completion can extend into cleanup.
// Dispatch here bypasses submitPacket, so the candidate's per-packet admission
// lock is excluded; BenchmarkWorkerReplay covers the real admission path.
func BenchmarkWorkerReplayProcessing(b *testing.B) {
	const segments = 4096
	input := filepath.Join(b.TempDir(), "processing.pcap")
	packets, wireBytes := workerReplayPCAP(b, input, segments)
	for _, workers := range []int{1, 4, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			var total workerReplayPhases
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				out := b.TempDir()
				b.StartTimer()
				phases := workerReplayRun(b, input, out, workers, 0, segments)
				total.Init += phases.Init
				total.Processing += phases.Processing
				total.Cleanup += phases.Cleanup
				b.StopTimer()
				workerReplayVerify(b, out, segments)
				if err := os.RemoveAll(out); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			b.StopTimer()
			b.ReportMetric(float64(total.Processing.Nanoseconds())/float64(b.N), "processing-ns/op")
			b.ReportMetric(float64(total.Init.Nanoseconds())/float64(b.N), "init-ns/op")
			b.ReportMetric(float64(total.Cleanup.Nanoseconds())/float64(b.N), "cleanup-ns/op")
			b.ReportMetric(float64(packets*b.N)/total.Processing.Seconds(), "processing-packets/s")
			b.ReportMetric(float64(packets), "packets/op")
			b.ReportMetric(float64(wireBytes), "wire-bytes/op")
		})
	}
}
