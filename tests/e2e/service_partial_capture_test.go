//go:build e2e

package e2e

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// The try.netcap.io arp-dns capture holds 3 Ethernet frames shorter than
// their header. Since v0.16.11 the helper exits 2 for that partial input, and
// service mode failed the analysis. A capture whose frames all fail at the
// link layer must still fail.
func TestServicePartialCapture(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	build := exec.Command("go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net/")
	build.Dir = root
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	for _, evidence := range servicePartialEvidenceModes {
		t.Run("capture-evidence="+evidence, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "data")
			if err := os.MkdirAll(filepath.Join(dataDir, "pcaps"), 0o700); err != nil {
				t.Fatal(err)
			}
			writePartialPCAPNG(t, filepath.Join(dataDir, "pcaps", "partial.pcapng"), 5)
			writePartialPCAPNG(t, filepath.Join(dataDir, "pcaps", "linkonly.pcapng"), 0)
			addr := freeLoopbackAddress(t)
			logPath := filepath.Join(t.TempDir(), "service.log")
			logFile, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			args := []string{"capture", "--service", "--http", addr, "--service-data-dir", dataDir, "-dpi=false"}
			if evidence != "default" {
				args = append(args, "--capture-evidence="+evidence)
			}
			cmd := exec.Command(binary, args...)
			cmd.Env = append(os.Environ(), "NC_CONFIG_ROOT="+t.TempDir())
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan struct{})
			go func() { _ = cmd.Wait(); close(exited) }()
			defer func() {
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-exited:
				case <-time.After(40 * time.Second):
					_ = cmd.Process.Kill()
					<-exited
				}
			}()
			base := "http://" + addr
			waitForService(t, base+"/health", exited, logPath)
			rows := waitForPreloads(t, base, []string{"partial.pcapng", "linkonly.pcapng"}, logPath)

			partial := rows["partial.pcapng"]
			if !partial.IsCompleted || partial.Error != "" || !strings.Contains(partial.Coverage, "link-errors=3") || !strings.Contains(partial.Coverage, "Ethernet packet too small") {
				t.Fatalf("partial capture: %+v\n%s", partial, readLog(logPath))
			}
			out := filepath.Join(dataDir, "results", partial.SessionID)
			var input struct {
				Status    string `json:"status"`
				Processed int64  `json:"processedPackets"`
				Link      int64  `json:"linkErrors"`
				Finalized bool   `json:"finalized"`
			}
			readJSON(t, filepath.Join(out, "capture-input.json"), &input)
			if input.Status != "partial" || input.Processed != 8 || input.Link != 3 || !input.Finalized {
				t.Fatalf("capture-input.json %+v", input)
			}
			_, manifestErr := os.Stat(filepath.Join(out, "capture-manifest.json"))
			if wantManifest := evidence != "false"; (manifestErr == nil) != wantManifest {
				t.Fatalf("manifest present=%v, want %v", manifestErr == nil, wantManifest)
			}
			if _, err := os.Stat(filepath.Join(out, "analysis_error.log")); err == nil {
				t.Fatal("analysis_error.log kept for a completed analysis")
			}
			if linkOnly := rows["linkonly.pcapng"]; linkOnly.IsCompleted || linkOnly.Error == "" {
				t.Fatalf("link-errors-only capture completed: %+v", linkOnly)
			}
		})
	}
}

type preloadRow struct {
	Name        string `json:"name"`
	SessionID   string `json:"sessionId"`
	IsCompleted bool   `json:"isCompleted"`
	Error       string `json:"error"`
	Coverage    string `json:"coverage"`
}

func waitForPreloads(t *testing.T, base string, names []string, logPath string) map[string]preloadRow {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		rows := map[string]preloadRow{}
		if resp, err := client.Get(base + "/api/files/input"); err == nil {
			var list []preloadRow
			_ = json.NewDecoder(resp.Body).Decode(&list)
			_ = resp.Body.Close()
			for _, row := range list {
				rows[row.Name] = row
			}
		}
		done := true
		for _, name := range names {
			row, ok := rows[name]
			done = done && ok && (row.IsCompleted || row.Error != "")
		}
		if done {
			return rows
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("preloads did not finish\n%s", readLog(logPath))
	return nil
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// writePartialPCAPNG writes good UDP frames followed by 3 frames of 8 bytes,
// too short for an Ethernet header.
func writePartialPCAPNG(t *testing.T, path string, good int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1700000000, 0)
	for i := range good {
		buf := gopacket.NewSerializeBuffer()
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1)}
		udp := &layers.UDP{SrcPort: layers.UDPPort(12000 + i), DstPort: 9999}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 1, 1}, EthernetType: layers.EthernetTypeIPv4},
			ip, udp, gopacket.Payload([]byte("partial-capture"))); err != nil {
			t.Fatal(err)
		}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Second), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 3 {
		short := []byte{2, 0, 0, 0, 1, 1, 2, 0}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(good+i) * time.Second), CaptureLength: len(short), Length: len(short)}, short); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
}

// Service mode honours --capture-evidence and defaults it on like the CLI.
var servicePartialEvidenceModes = []string{"default", "false", "true"}
