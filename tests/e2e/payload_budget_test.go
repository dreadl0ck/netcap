//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/stream/tcp"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

func TestTCPRetentionBudgetCLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temporary := t.TempDir()
	binary := filepath.Join(temporary, "net")
	build := exec.Command("go", "build", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
	build.Dir, build.Env = root, append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	capture := filepath.Join(temporary, "owned.pcap")
	writeAuditSemanticCapture(t, capture)
	configuration := filepath.Join(temporary, "config")
	environment := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + temporary, "TMPDIR=" + os.TempDir(), "NC_CONFIG_ROOT=" + configuration}
	required := []string{"HTTP", "DNS", "Kerberos", "TACACS", "IPP", "Zabbix", "Protobuf", "OPCUA", "S7Comm", "PROFINET", "RDP", "TLSCertificate"}
	var baseline map[string][]string
	for _, workers := range []int{1, 2, 4, 8} {
		for _, limit := range []int64{0, 1, 1 << 20} {
			t.Run(fmt.Sprintf("workers=%d/limit=%d", workers, limit), func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "audit")
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				command := exec.CommandContext(ctx, binary, "capture", "-read", capture, "-out", out, "-workers", fmt.Sprint(workers), "-max-retained-tcp-bytes", fmt.Sprint(limit), "-include", strings.Join(append(required, "TCP", "Connection"), ","), "-capture-evidence=true", "-compress=false", "-dpi=false", "-geoDB=false", "-network-detection=false", "-fileStorage", "", "-http", "", "-quiet", "-y")
				command.Env = environment
				output, runErr := command.CombinedOutput()
				var manifest evidence.CaptureManifest
				read := func(name string, target any) {
					t.Helper()
					data, err := os.ReadFile(filepath.Join(out, name))
					if err != nil {
						t.Fatalf("%s: %v; capture=%v %s", name, err, runErr, output)
					}
					if err := json.Unmarshal(data, target); err != nil {
						t.Fatal(err)
					}
				}
				read("capture-manifest.json", &manifest)
				var health tcp.ReassemblyHealth
				read("TCPReassemblyHealth.json", &health)
				if manifest.Config.MaxRetainedTCPBytes != limit {
					t.Fatal("CLI did not bind retention configuration to the manifest")
				}
				if limit > 0 && (health.RetainedPayload == nil || health.RetainedPayload.LimitBytes != limit || health.RetainedPayload.PeakBytes > limit || health.RetainedPayload.RetainedBytes != 0) {
					t.Fatalf("CLI did not propagate shared budget: %+v", health.RetainedPayload)
				}
				if limit == 0 && health.RetainedPayload != nil {
					t.Fatal("disabled budget was reported as configured")
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if limit == 1 {
					if runErr == nil || !strings.Contains(string(output), "TCP retained payload budget exceeded") || manifest.Status != "error" || !os.IsNotExist(readyErr) {
						t.Fatalf("budget failure became CLI success: %v status=%s ready=%v %s", runErr, manifest.Status, readyErr, output)
					}
				} else {
					if runErr != nil || manifest.Status != "done" || readyErr != nil || (limit > 0 && health.RetainedPayload.PeakBytes == 0) {
						t.Fatalf("healthy capture failed: %v status=%s ready=%v %s", runErr, manifest.Status, readyErr, output)
					}
					semantic := make(map[string][]string)
					for _, name := range required {
						records := readSemanticRecords(t, out, name)
						if len(records) == 0 {
							t.Fatalf("required %s records missing", name)
						}
						for _, record := range records {
							data, err := json.Marshal(record)
							if err != nil {
								t.Fatal(err)
							}
							semantic[name] = append(semantic[name], string(data))
						}
						sort.Strings(semantic[name])
					}
					if baseline == nil {
						baseline = semantic
					} else if !reflect.DeepEqual(semantic, baseline) {
						t.Fatalf("configured memory budget or workers changed complete semantic output (workers=%d limit=%d)", workers, limit)
					}
				}
			})
		}
	}
	for _, fromEnvironment := range []bool{false, true} {
		arguments := []string{"capture"}
		childEnvironment := append([]string{}, environment...)
		if fromEnvironment {
			childEnvironment = append(childEnvironment, "NC_MAX_RETAINED_TCP_BYTES=-1")
		} else {
			arguments = append(arguments, "-max-retained-tcp-bytes=-1")
		}
		command := exec.Command(binary, arguments...)
		command.Env = childEnvironment
		if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "max-retained-tcp-bytes cannot be negative") {
			t.Fatalf("invalid budget accepted (environment=%v): %v %s", fromEnvironment, err, output)
		}
	}
}
