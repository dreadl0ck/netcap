//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func reorderApplicationCapture(t *testing.T, input, output string) {
	t.Helper()
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	type frame struct {
		ci   gopacket.CaptureInfo
		data []byte
	}
	var frames []frame
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame{ci, append([]byte(nil), data...)})
	}
	swapped := false
	for i := 0; i+1 < len(frames); i++ {
		a := gopacket.NewPacket(frames[i].data, layers.LayerTypeEthernet, gopacket.Default)
		b := gopacket.NewPacket(frames[i+1].data, layers.LayerTypeEthernet, gopacket.Default)
		x, xok := a.TransportLayer().(*layers.TCP)
		y, yok := b.TransportLayer().(*layers.TCP)
		if xok && yok && len(x.Payload) > 0 && len(y.Payload) > 0 && x.TransportFlow() == y.TransportFlow() && a.NetworkLayer().NetworkFlow() == b.NetworkLayer().NetworkFlow() {
			frames[i], frames[i+1] = frames[i+1], frames[i]
			swapped = true
			break
		}
	}
	if !swapped {
		t.Fatal("negative control requires an actual TCP sequence hole")
	}
	out, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriterNanos(out)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if err := w.WritePacket(f.ci, f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReassemblyPageBudgetCLI(t *testing.T) {
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
	ordered, capture := filepath.Join(temporary, "ordered.pcap"), filepath.Join(temporary, "reordered.pcap")
	writeAuditSemanticCapture(t, ordered)
	reorderApplicationCapture(t, ordered, capture)
	environment := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + temporary, "TMPDIR=" + os.TempDir(), "NC_CONFIG_ROOT=" + filepath.Join(temporary, "config")}
	var baseline []string
	for _, workers := range []int{1, 2, 4, 8} {
		for _, limit := range []int64{0, 1, 1 << 20} {
			t.Run(fmt.Sprintf("workers=%d/limit=%d", workers, limit), func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "audit")
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				command := exec.CommandContext(ctx, binary, "capture", "-read", capture, "-out", out, "-workers", fmt.Sprint(workers), "-max-retained-reassembly-bytes", fmt.Sprint(limit), "-include", "TCP,Connection,HTTP", "-capture-evidence=true", "-compress=false", "-dpi=false", "-geoDB=false", "-network-detection=false", "-fileStorage", "", "-http", "", "-quiet", "-y")
				command.Env = environment
				output, runErr := command.CombinedOutput()
				var manifest evidence.CaptureManifest
				data, err := os.ReadFile(filepath.Join(out, "capture-manifest.json"))
				if err != nil {
					t.Fatalf("manifest: %v capture=%v %s", err, runErr, output)
				}
				if err := json.Unmarshal(data, &manifest); err != nil {
					t.Fatal(err)
				}
				if manifest.Config.MaxRetainedReassemblyBytes != limit {
					t.Fatal("CLI lost effective page budget")
				}
				_, readyErr := os.Stat(filepath.Join(out, evidence.AuditReadyFile))
				if limit > 0 {
					data, err = os.ReadFile(filepath.Join(out, "TCPReassemblyPageBudget.json"))
					if err != nil {
						t.Fatal(err)
					}
					var health reassembly.PageBudgetHealth
					if err := json.Unmarshal(data, &health); err != nil {
						t.Fatal(err)
					}
					if health.LimitBytes != limit || health.PeakBytes > limit || health.RetainedBytes != 0 || (limit > 1 && health.PeakBytes == 0) {
						t.Fatal(health)
					}
				}
				if limit == 1 {
					if runErr == nil || manifest.Status != "error" || !os.IsNotExist(readyErr) || !strings.Contains(string(output), "reassembly page budget exceeded") {
						t.Fatalf("failure became success: %v %s %s", runErr, manifest.Status, output)
					}
					return
				}
				if runErr != nil || manifest.Status != "done" || readyErr != nil {
					t.Fatalf("healthy control failed: %v %s", runErr, output)
				}
				records := readSemanticRecords(t, out, "HTTP")
				if len(records) == 0 {
					t.Fatal("reordered complete HTTP transactions missing")
				}
				var semantic []string
				for _, record := range records {
					data, err := json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
					semantic = append(semantic, string(data))
				}
				sort.Strings(semantic)
				if baseline == nil {
					baseline = semantic
				} else if !reflect.DeepEqual(baseline, semantic) {
					t.Fatal("worker count or page budget changed HTTP semantics")
				}
			})
		}
	}
	for _, fromEnvironment := range []bool{false, true} {
		args, env := []string{"capture"}, append([]string(nil), environment...)
		if fromEnvironment {
			env = append(env, "NC_MAX_RETAINED_REASSEMBLY_BYTES=-1")
		} else {
			args = append(args, "-max-retained-reassembly-bytes=-1")
		}
		command := exec.Command(binary, args...)
		command.Env = env
		if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "max-retained-reassembly-bytes cannot be negative") {
			t.Fatalf("invalid budget accepted: %v %s", err, output)
		}
	}
}
