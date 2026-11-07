package collector

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/resolvers"
)

type inputReproResult struct {
	Packets uint64 `json:"packets"`
	Error   string `json:"error,omitempty"`
}

// Separate processes isolate the decoder registries and retain real collector output.
func TestCaptureInputProcess(t *testing.T) {
	input, out := os.Getenv("NETCAP_INPUT_CHILD"), os.Getenv("NETCAP_INPUT_CHILD_OUT")
	if input == "" {
		return
	}
	workers, err := strconv.Atoi(os.Getenv("NETCAP_INPUT_WORKERS"))
	if err != nil {
		t.Fatal(err)
	}
	resolvers.DataBaseFolderPath = t.TempDir()
	cfg := ultimateCaptureConfig(out, workers, 0)
	cfg.CaptureEvidence, cfg.RetainPackets = true, true
	cfg.LogErrors, cfg.WriteUnknownPackets = true, true
	c := New(cfg)
	collect := c.CollectPcap
	if isPCAPNG(t, input) {
		collect = c.CollectPcapNG
	}
	err = collect(input)
	result := inputReproResult{Packets: c.admittedPackets}
	if err != nil {
		result.Error = err.Error()
	}
	writeInputJSON(t, filepath.Join(out, "result.json"), result)
}

func writeInputJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

func runInputRepro(t *testing.T, input, out string, workers int) inputReproResult {
	t.Helper()
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureInputProcess$", "-test.count=1", "-test.timeout=80s")
	cmd.Env = append(os.Environ(), "NETCAP_INPUT_CHILD="+input, "NETCAP_INPUT_CHILD_OUT="+out, fmt.Sprintf("NETCAP_INPUT_WORKERS=%d", workers))
	output, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(filepath.Join(out, "process.log"), output, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatalf("collector process: %v\n%s", err, output)
	}
	data, err := os.ReadFile(filepath.Join(out, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result inputReproResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCaptureInputCorpus(t *testing.T) {
	root := os.Getenv("NETCAP_INPUT_CORPUS")
	if root == "" {
		t.Skip("set NETCAP_INPUT_CORPUS; NETCAP_INPUT_FETCH=1 permits bounded pinned downloads")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("NETCAP_INPUT_CORPUS must be absolute")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/round2-input/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Samples []struct {
			Error                             bool
			Name, URL, SHA256, Status, Record string
			Size, Packets                     int
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, sample := range manifest.Samples {
		t.Run(sample.Name, func(t *testing.T) {
			path := filepath.Join(root, sample.Name+".pcap")
			data, err := os.ReadFile(path)
			if os.IsNotExist(err) && os.Getenv("NETCAP_INPUT_FETCH") == "1" {
				client := http.Client{Timeout: 30 * time.Second}
				resp, fetchErr := client.Get(sample.URL)
				if fetchErr != nil {
					t.Fatal(fetchErr)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK || sample.Size > 1<<20 {
					t.Fatalf("fetch status %s or size out of bounds", resp.Status)
				}
				data, err = io.ReadAll(io.LimitReader(resp.Body, int64(sample.Size)+1))
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != sample.Size || fmt.Sprintf("%x", sha256.Sum256(data)) != sample.SHA256 {
				t.Fatal("fixture size/SHA-256 mismatch")
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var previous map[string]string
			for _, workers := range []int{1, 4} {
				out := t.TempDir()
				if saved := os.Getenv("NETCAP_INPUT_RESULTS"); saved != "" {
					out = filepath.Join(saved, fmt.Sprintf("%s-w%d", sample.Name, workers))
				}
				result := runInputRepro(t, path, out, workers)
				t.Logf("workers=%d packets=%d error=%q output=%s", workers, result.Packets, result.Error, out)
				if os.Getenv("NETCAP_INPUT_BASELINE") == "1" {
					continue
				}
				if int(result.Packets) != sample.Packets || (result.Error != "") != sample.Error {
					t.Fatalf("unexpected capture result: %+v, want %d packets / %s", result, sample.Packets, sample.Status)
				}
				var report CaptureInputReport
				readInputJSON(t, filepath.Join(out, "capture-input.json"), &report)
				if report.Status != sample.Status || report.CountedPackets != int64(sample.Packets) || report.ProcessedPackets != int64(sample.Packets) || !report.ReachedEOF {
					t.Fatalf("input report: %+v", report)
				}
				var capture evidence.CaptureManifest
				readInputJSON(t, filepath.Join(out, "capture-manifest.json"), &capture)
				wantStatus := "done"
				if sample.Status == "partial" {
					wantStatus = "partial"
				}
				if sample.Error {
					wantStatus = "error"
				}
				if capture.Status != wantStatus || capture.AdmittedPackets != result.Packets || capture.InputSHA256 != sample.SHA256 {
					t.Fatalf("capture manifest: %+v", capture)
				}
				if sample.Record != "" {
					counts, digests := ultimateRecords(t, out)
					if counts[sample.Record] == 0 {
						t.Fatalf("missing %s audit records", sample.Record)
					}
					t.Logf("audit counts: %v", counts)
					stable := map[string]string{}
					for _, name := range []string{"IPv4", "IPv6", "TCP", "UDP", "HTTP", "SMB", "ICMPv4", "ARP"} {
						if value, ok := digests[name]; ok {
							stable[name] = value
						}
					}
					if previous != nil && !reflect.DeepEqual(previous, stable) {
						t.Fatalf("worker-count record drift: %v vs %v", previous, stable)
					}
					previous = stable
				}
			}
		})
	}
}

func readInputJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}
