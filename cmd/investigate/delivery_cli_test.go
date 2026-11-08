//go:build e2e

package investigate

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/delivery"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestAlertDeliveryCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "net")
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOWORK=off", "GOMAXPROCS=2")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	dir := t.TempDir()
	outbox := t.TempDir()
	w, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.WriteAlert(&types.Alert{Timestamp: 42, RuleName: "fixture", MatchedRecord: `{"Password":"never-send-this"}`}); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		var notice delivery.Notice
		if json.NewDecoder(r.Body).Decode(&notice) != nil || notice.Rule != "fixture" || r.Header.Get("Idempotency-Key") == "" {
			t.Error("invalid webhook")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	args := []string{"investigate", "deliver-alerts", "-read", dir, "-outbox", outbox, "-scope", "synthetic/capture", "-endpoint", server.URL, "-timeout", "10s"}
	for i := 0; i < 2; i++ {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "NC_CONFIG_ROOT=" + t.TempDir(), "NETCAP_ALERT_WEBHOOK_TOKEN=local-test-only"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI: %v\n%s", err, out)
		}
		if strings.Contains(string(out), "never-send-this") || strings.Contains(string(out), "local-test-only") {
			t.Fatal("CLI leaked secrets")
		}
		var status delivery.Status
		if json.Unmarshal(out, &status) != nil || status.Delivered != 1 || status.Pending != 0 {
			t.Fatalf("status: %s", out)
		}
	}
	if attempts.Load() != 1 {
		t.Fatal("CLI restart repeated acknowledged notice", attempts.Load())
	}
	// Redirects are retained as rejected and make the actual command nonzero.
	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", server.URL)
		w.WriteHeader(302)
	}))
	defer reject.Close()
	args[5] = t.TempDir()
	args[9] = reject.URL
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "NC_CONFIG_ROOT=" + t.TempDir()}
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), `"rejected":1`) {
		t.Fatalf("rejected CLI: %v %s", err, out)
	}
	t.Run("capture-time-grouping", func(t *testing.T) {
		pcap := filepath.Join(t.TempDir(), "scoped.pcap")
		f, err := os.Create(pcap)
		if err != nil {
			t.Fatal(err)
		}
		pw := pcapgo.NewWriter(f)
		if err = pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
		// Deliberately reversed capture timestamps: one 50-request group and two
		// unrelated 25-request groups, evaluated with a declared 600s allowance.
		for i := 99; i >= 0; i-- {
			src := "192.0.2.1"
			if i >= 50 && i < 75 {
				src = "192.0.2.3"
			}
			if i >= 75 {
				src = "192.0.2.4"
			}
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP("192.0.2.2").To4()}
			tcp := &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: 443, SYN: true, Seq: uint32(i), Window: 1024}
			_ = tcp.SetNetworkLayerForChecksum(ip)
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
			buffer := gopacket.NewSerializeBuffer()
			if err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp); err != nil {
				t.Fatal(err)
			}
			b := buffer.Bytes()
			if err = pw.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(b), Length: len(b)}, b); err != nil {
				t.Fatal(err)
			}
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		rule := filepath.Join(t.TempDir(), "scoped.yml")
		if err = os.WriteFile(rule, []byte("capture_time:\n  scope: synthetic-capture/source\n  lateness_seconds: 600\nrules:\n- name: scoped-cli\n  type: TCP\n  expression: SYN\n  enabled: true\n  threshold: 50\n  threshold_window: 600\n  group_by: [SrcIP, DstIP, DstPort]\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, workers := range []string{"1", "4"} {
			outDir := t.TempDir()
			capture := exec.CommandContext(ctx, binary, "capture", "-read", pcap, "-out", outDir, "-rules", rule, "-workers", workers, "-include", "TCP", "-context=true", "-dpi=false", "-geoDB=false", "-network-detection=false", "-quiet", "-http", "")
			capture.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "NC_CONFIG_ROOT=" + t.TempDir(), "GOMAXPROCS=2"}
			if out, err := capture.CombinedOutput(); err != nil {
				t.Fatalf("capture: %v %s", err, out)
			}
			tail, err := rules.OpenAlertTail(filepath.Join(outDir, "Alert.ncap.gz"), "")
			if err != nil {
				t.Fatal(err)
			}
			event, err := tail.Next()
			if err != nil || event.Alert.SrcIP != "192.0.2.1" || event.Alert.Timestamp != time.Unix(1700000049, 0).UnixNano() {
				t.Fatal(event, err)
			}
			if _, err = tail.Next(); err != rules.ErrAlertNotReady {
				t.Fatal("unrelated groups combined", err)
			}
			tail.Close()
		}
	})
}
