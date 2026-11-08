//go:build e2e && !noyara

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestArtifactAnalysisCLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	build := exec.Command("go", "build", "-tags=nodpi,nomagika", "-o", binary, "./cmd/net")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	body := []byte("OWNED_BATCH2_MARKER\x00\xff\r\n")
	captures := map[string]string{"HTTP": filepath.Join(temp, "http.pcap"), "SMTP": filepath.Join(temp, "smtp.pcap")}
	writeArtifactHTTPPCAP(t, captures["HTTP"], body)
	message := "From: owned@example.test\r\nTo: analyst@example.test\r\nContent-Type: multipart/mixed; boundary=owned\r\n\r\n"
	for _, name := range []string{"one.bin", "two.bin"} {
		message += "--owned\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=" + name + "\r\nContent-Transfer-Encoding: binary\r\n\r\n" + string(body) + "\r\n"
	}
	message += "--owned--\r\n"
	request := []byte("EHLO fixture\r\nMAIL FROM:<owned@example.test>\r\nRCPT TO:<analyst@example.test>\r\nDATA\r\n" + message + ".\r\nQUIT\r\n")
	response := []byte("220 fixture SMTP\r\n250 fixture\r\n250 sender OK\r\n250 recipient OK\r\n354 send data\r\n250 accepted\r\n221 bye\r\n")
	writeArtifactTCPPCAP(t, captures["SMTP"], request, response, 25)
	ruleDir := filepath.Join(temp, "rules")
	if err := os.Mkdir(ruleDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ruleDir, "owned.yar"), []byte(`rule owned { strings:$x="OWNED_BATCH2_MARKER" condition:$x }`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"HTTP", "SMTP"} {
		for _, workers := range []int{1, 4} {
			t.Run(protocol+"/"+fmt.Sprint(workers), func(t *testing.T) {
				// Marshal through YAML because this tests actual CLI configuration admission.
				configPath := filepath.Join(t.TempDir(), "file.yaml")
				rulesPath, _ := json.Marshal(ruleDir)
				config := fmt.Sprintf("file_extraction:\n  advanced:\n    enable_yara_scanning: true\n    yara_rules_path: %s\n", rulesPath)
				if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(t.TempDir(), "out")
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				include := protocol + ",File"
				if protocol == "SMTP" {
					include += ",Mail"
				}
				cmd := exec.CommandContext(ctx, binary, "capture", "-read", captures[protocol], "-out", out, "-include", include, "-workers", fmt.Sprint(workers), "-file-config", configPath, "-fileStorage", "files", "-context=true", "-capture-evidence=true", "-compress=false", "-dpi=false", "-geoDB=false", "-network-detection=false", "-http", "", "-quiet", "-y")
				cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+filepath.Join(temp, "config"), "NETCAP_GEOIP_LIVE_TEST=0")
				if b, e := cmd.CombinedOutput(); e != nil {
					t.Fatalf("capture: %v %s", e, b)
				}
				var report file.AnalysisReport
				offlineCLIReadJSON(t, filepath.Join(out, file.AnalysisReportFile), &report)
				var manifest evidence.CaptureManifest
				offlineCLIReadJSON(t, filepath.Join(out, "capture-manifest.json"), &manifest)
				if report.State != "complete" || report.RunID != manifest.RunID || len(report.Results) != 1 {
					t.Fatalf("report: %+v", report)
				}
				if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); err != nil {
					t.Fatal("results not finalized before readiness", err)
				}
				reader, err := netio.Open(filepath.Join(out, "File.ncap"), defaults.BufferSize)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				if _, err := reader.ReadHeader(); err != nil {
					t.Fatal(err)
				}
				count := 0
				paths := map[string]bool{}
				hash := sha256.Sum256(body)
				for {
					var record types.File
					err := reader.Next(&record)
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					count++
					if record.Protocol != protocol {
						t.Fatalf("protocol attribution lost: %s", record.Protocol)
					}
					if protocol == "SMTP" && (record.ParentFileID == "" || record.FlowDirection != "client_to_server") {
						t.Fatal("mail occurrence/direction provenance lost")
					}
					paths[record.Location] = true
					if record.Hashes == nil || record.Hashes.SHA256 != hex.EncodeToString(hash[:]) || len(record.YaraMatches) != 1 || record.YaraMatches[0] != "owned" {
						t.Fatalf("file evidence: %+v", record)
					}
					data, e := os.ReadFile(record.Location)
					if e != nil || string(data) != string(body) {
						t.Fatal("attachment bytes changed", e)
					}
				}
				if count != 2 || len(paths) != 1 {
					t.Fatalf("occurrences=%d blobs=%d", count, len(paths))
				}
			})
		}
	}
	if baseline := os.Getenv("NETCAP_ARTIFACT_BASELINE_BINARY"); baseline != "" {
		qualifyArtifactPerformance(t, baseline, binary, temp)
	}
}

func qualifyArtifactPerformance(t *testing.T, baseline, current, temp string) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Fatal("the optional resident-set measurement currently uses macOS /usr/bin/time -l")
	}
	body := strings.Repeat("owned-performance-fixture-", 2048)
	request := strings.Repeat("GET /owned.bin HTTP/1.1\r\nHost: example.test\r\n\r\n", 32)
	response := strings.Repeat(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n%s", len(body), body), 32)
	capture := filepath.Join(temp, "performance.pcap")
	writeArtifactTCPPCAP(t, capture, []byte(request), []byte(response), 80)
	for _, entry := range []struct{ name, binary string }{{"baseline", baseline}, {"batch2", current}} {
		var wall []float64
		var rss []int64
		for run := 0; run < 3; run++ {
			out := filepath.Join(t.TempDir(), "out")
			cmd := exec.Command("/usr/bin/time", "-l", entry.binary, "capture", "-read", capture, "-out", out, "-include", "HTTP,File", "-fileStorage", "files", "-workers", "4", "-compress=false", "-dpi=false", "-geoDB=false", "-network-detection=false", "-http", "", "-quiet", "-y")
			cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+filepath.Join(temp, "benchmark-config"))
			started := time.Now()
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s performance capture: %v %s", entry.name, err, b)
			}
			wall = append(wall, time.Since(started).Seconds())
			var resident int64
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "maximum resident set size") {
					resident, _ = strconv.ParseInt(strings.Fields(line)[0], 10, 64)
				}
			}
			if resident <= 0 {
				t.Fatal("missing resident-set measurement")
			}
			rss = append(rss, resident)
			reader, err := netio.Open(filepath.Join(out, "File.ncap"), defaults.BufferSize)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.ReadHeader(); err != nil {
				t.Fatal(err)
			}
			count := 0
			want := sha256.Sum256([]byte(body))
			for {
				var record types.File
				err := reader.Next(&record)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				count++
				if record.Hashes == nil || record.Hashes.SHA256 != hex.EncodeToString(want[:]) {
					t.Fatal("performance comparison did different extraction work")
				}
			}
			reader.Close()
			if count != 32 {
				t.Fatalf("%s extracted %d records, want 32", entry.name, count)
			}
		}
		sort.Float64s(wall)
		sort.Slice(rss, func(i, j int) bool { return rss[i] < rss[j] })
		t.Logf("ARTIFACT_BENCH %s: 32 equal %d-byte artifacts, analyzers disabled, 3 runs; median wall %.3fs, median max RSS %d bytes", entry.name, len(body), wall[1], rss[1])
	}
}

func writeArtifactHTTPPCAP(t *testing.T, path string, body []byte) {
	request := []byte("GET /one.bin HTTP/1.1\r\nHost: example.test\r\n\r\nGET /two.bin HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n%sHTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n%s", len(body), body, len(body), body))
	writeArtifactTCPPCAP(t, path, request, response, 80)
}

func writeArtifactTCPPCAP(t *testing.T, path string, request, response []byte, port layers.TCPPort) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	type packet struct {
		server, syn, ack, fin bool
		seq, an               uint32
		data                  []byte
	}
	packets := []packet{{false, true, false, false, 100, 0, nil}, {true, true, true, false, 500, 101, nil}, {false, false, true, false, 101, 501, nil}, {false, false, true, false, 101, 501, request}, {true, false, true, false, 501, 101 + uint32(len(request)), response}, {false, false, true, true, 101 + uint32(len(request)), 501 + uint32(len(response)), nil}, {true, false, true, true, 501 + uint32(len(response)), 102 + uint32(len(request)), nil}, {false, false, true, false, 102 + uint32(len(request)), 502 + uint32(len(response)), nil}}
	var split []packet
	for _, p := range packets {
		if len(p.data) == 0 {
			split = append(split, p)
			continue
		}
		for offset := 0; offset < len(p.data); offset += 1400 {
			chunk := p
			chunk.seq += uint32(offset)
			chunk.data = p.data[offset:min(len(p.data), offset+1400)]
			split = append(split, chunk)
		}
	}
	packets = split
	for i, p := range packets {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1)}
		tcp := &layers.TCP{SrcPort: 12345, DstPort: port, SYN: p.syn, ACK: p.ack, FIN: p.fin, Seq: p.seq, Ack: p.an, Window: 4096, PSH: len(p.data) > 0}
		if p.server {
			ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
			tcp.SrcPort, tcp.DstPort = tcp.DstPort, tcp.SrcPort
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		b := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(p.data)); err != nil {
			t.Fatal(err)
		}
		data := b.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000, int64(i)*1000000), CaptureLength: len(data), Length: len(data)}, data); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
