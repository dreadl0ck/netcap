//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket/pcap"
)

func incrementalCLIBinary(t *testing.T) (string, []string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "net")
	build := exec.Command("go", "build", "-p=2", "-o", binary, "./cmd/net")
	build.Dir, build.Env = root, append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("native build: %v %s", err, output)
	}
	return binary, []string{"PATH=" + os.Getenv("PATH"), "HOME=" + temporary, "TMPDIR=" + os.TempDir(), "NC_CONFIG_ROOT=" + filepath.Join(temporary, "config")}
}

func incrementalCLIRecords(out string) (int, bool, error) {
	r, err := netio.Open(filepath.Join(out, "HTTP.ncap"), 4096)
	if err != nil {
		return 0, false, err
	}
	if _, err = r.ReadHeader(); err != nil {
		r.Close()
		return 0, false, err
	}
	count := 0
	for {
		row := new(types.HTTP)
		err = r.Next(row)
		if err == io.EOF {
			break
		}
		if err != nil {
			r.Close()
			return count, false, err
		}
		count++
	}
	r.Close()
	r, err = netio.Open(filepath.Join(out, "Alert.ncap.gz"), 4096)
	if err != nil {
		return count, false, err
	}
	defer r.Close()
	if _, err = r.ReadHeader(); err != nil {
		return count, false, err
	}
	scan := false
	for {
		row := new(types.Alert)
		err = r.Next(row)
		if err == io.EOF {
			return count, scan, nil
		}
		if err != nil {
			return count, scan, err
		}
		scan = scan || row.Name == "http.scan"
	}
}

func TestIncrementalHTTPLiveCLI(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("qualified native loopback capture platforms: Darwin/Linux")
	}
	iface := "lo"
	if runtime.GOOS == "darwin" {
		iface = "lo0"
	}
	handle, err := pcap.OpenLive(iface, 65535, false, 50*time.Millisecond)
	if err != nil {
		t.Skipf("live capture unavailable: %v", err)
	}
	handle.Close()
	binary, environment := incrementalCLIBinary(t)
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var opened, closed atomic.Int64
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "0")
				w.WriteHeader(404)
			}), ConnState: func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					opened.Add(1)
				}
				if state == http.StateClosed {
					closed.Add(1)
				}
			}}
			go server.Serve(listener)
			defer server.Close()
			out := filepath.Join(t.TempDir(), "audit")
			logPath := filepath.Join(t.TempDir(), "capture.log")
			log, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "capture", "-iface", iface, "-bpf", fmt.Sprintf("tcp port %d", listener.Addr().(*net.TCPAddr).Port), "-out", out, "-workers", fmt.Sprint(workers), "-incremental-http", "-max-retained-tcp-state-bytes", "1048576", "-max-retained-tcp-bytes", "65536", "-live-maintenance-interval", "50ms", "-live-flush-interval", "50ms", "-include", "TCP,Connection,HTTP", "-capture-evidence=true", "-compress=false", "-dpi=false", "-geoDB=false", "-fileStorage", "", "-http", "", "-quiet", "-y")
			command.Env, command.Stdout, command.Stderr = environment, log, log
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			stopped := false
			defer func() {
				if !stopped {
					command.Process.Signal(os.Interrupt)
					select {
					case <-done:
					case <-time.After(10 * time.Second):
						command.Process.Kill()
						<-done
					}
				}
			}()
			deadline := time.Now().Add(15 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(out, "capture-manifest.json")); err == nil {
					break
				}
				select {
				case err := <-done:
					stopped = true
					data, _ := os.ReadFile(logPath)
					t.Fatalf("capture exited during startup: %v %s", err, data)
				default:
				}
				if time.Now().After(deadline) {
					t.Fatal("capture manifest unavailable")
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)
			transport := &http.Transport{MaxConnsPerHost: 1, DisableCompression: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for i := range 40 {
				response, err := client.Get(fmt.Sprintf("http://%s/missing/%d", listener.Addr(), i))
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			var count int
			var scan bool
			var readErr error
			for time.Now().Before(deadline) {
				count, scan, readErr = incrementalCLIRecords(out)
				if count == 40 && scan && readErr == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if count != 40 || !scan || readErr != nil {
				data, _ := os.ReadFile(logPath)
				t.Fatalf("before-close emission failed: rows=%d scan=%v err=%v\n%s", count, scan, readErr, data)
			}
			if opened.Load() != 1 || closed.Load() != 0 {
				t.Fatal("test did not retain one open keepalive connection", opened.Load(), closed.Load())
			}
			select {
			case err := <-done:
				stopped = true
				t.Fatal("capture ended before evidence assertion", err)
			default:
			}
			if _, err := os.Stat(filepath.Join(out, evidence.AuditReadyFile)); !os.IsNotExist(err) {
				t.Fatal("active capture became ready", err)
			}
			command.Process.Signal(os.Interrupt)
			select {
			case err := <-done:
				stopped = true
				if err != nil {
					data, _ := os.ReadFile(logPath)
					t.Fatalf("graceful shutdown: %v %s", err, data)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("capture cancellation did not join")
			}
			if count, _, err := incrementalCLIRecords(out); err != nil || count != 40 {
				t.Fatal("shutdown duplicated/lost completed records", count, err)
			}
			data, err := os.ReadFile(filepath.Join(out, "TCPIncrementalHealth.json"))
			if err != nil {
				t.Fatal(err)
			}
			var health tcp.IncrementalHealth
			if err := json.Unmarshal(data, &health); err != nil {
				t.Fatal(err)
			}
			if health.IncrementalStreams != 1 || health.CompletedTransactions != 40 {
				t.Fatal(health)
			}
		})
	}
}

func TestIncrementalHTTPStateBudgetCLI(t *testing.T) {
	binary, environment := incrementalCLIBinary(t)
	capture := filepath.Join(t.TempDir(), "owned.pcap")
	writeAuditSemanticCapture(t, capture)
	for _, workers := range []int{1, 4} {
		for _, limit := range []int64{0, 1000, 1 << 20} {
			t.Run(fmt.Sprintf("workers=%d/limit=%d", workers, limit), func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "audit")
				command := exec.Command(binary, "capture", "-read", capture, "-out", out, "-workers", fmt.Sprint(workers), "-incremental-http", "-capture-time-idle-expiry", "-max-retained-tcp-state-bytes", fmt.Sprint(limit), "-include", "TCP,Connection,HTTP", "-capture-evidence=true", "-compress=false", "-dpi=false", "-geoDB=false", "-network-detection=false", "-fileStorage", "", "-http", "", "-quiet", "-y")
				command.Env = environment
				output, runErr := command.CombinedOutput()
				read := func(name string, target any) {
					t.Helper()
					data, err := os.ReadFile(filepath.Join(out, name))
					if err != nil {
						t.Fatalf("%s: %v capture=%v %s", name, err, runErr, output)
					}
					if err := json.Unmarshal(data, target); err != nil {
						t.Fatal(err)
					}
				}
				var manifest evidence.CaptureManifest
				var health core.StateBudgetHealth
				read("capture-manifest.json", &manifest)
				read("TCPStreamStateBudget.json", &health)
				if !manifest.Config.IncrementalHTTP || !manifest.Config.CaptureTimeIdleExpiry || manifest.Config.MaxRetainedTCPStateBytes != limit || health.RetainedBytes != 0 || limit > 0 && health.PeakBytes > limit {
					t.Fatal(manifest.Config, health)
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if limit == 1000 {
					if runErr == nil || manifest.Status != "error" || !os.IsNotExist(readyErr) || !health.Exceeded {
						t.Fatalf("budget failure became ready: %v %s %+v %s", runErr, manifest.Status, health, output)
					}
				} else {
					if runErr != nil || manifest.Status != "done" || readyErr != nil || health.Exceeded {
						t.Fatalf("healthy capture failed: %v %s %+v %s", runErr, manifest.Status, health, output)
					}
				}
			})
		}
	}
	for _, env := range []bool{false, true} {
		args, childEnv := []string{"capture"}, append([]string(nil), environment...)
		if env {
			childEnv = append(childEnv, "NC_MAX_RETAINED_TCP_STATE_BYTES=-1")
		} else {
			args = append(args, "-max-retained-tcp-state-bytes=-1")
		}
		command := exec.Command(binary, args...)
		command.Env = childEnv
		if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "max-retained-tcp-state-bytes cannot be negative") {
			t.Fatal("negative state budget accepted", err, string(output))
		}
	}
}
