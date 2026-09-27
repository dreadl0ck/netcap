package collector

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wiresharkFixtureDir = "testdata/wireshark"

type wiresharkSample struct {
	Name          string `json:"name"`
	SHA256        string `json:"sha256"`
	CaptureSHA256 string `json:"capture_sha256"`
	Group         string `json:"group"`
	Unsupported   string `json:"unsupported"`
	Quick         bool   `json:"quick"`
	Sampled       bool   `json:"sampled"`
	QuickSHA256   string `json:"quick_sha256"`
	Record        string `json:"record"`
}

func wiresharkSamples(tb testing.TB) []wiresharkSample {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join(wiresharkFixtureDir, "manifest.json"))
	if err != nil {
		tb.Fatal(err)
	}
	var manifest struct {
		Samples []wiresharkSample `json:"samples"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		tb.Fatal(err)
	}
	if len(manifest.Samples) == 0 {
		tb.Fatal("empty Wireshark corpus")
	}
	return manifest.Samples
}

func wiresharkCaptureName(name string) string {
	return strings.TrimSuffix(name, ".gz") + ".bin"
}

func wiresharkVerifyCapture(tb testing.TB, path string, sample wiresharkSample) {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("required sample %s: %v", path, err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != sample.CaptureSHA256 {
		tb.Fatalf("%s: capture sha256 %s, want %s", path, got, sample.CaptureSHA256)
	}
}

func TestWiresharkQuickSamples(t *testing.T) {
	quick, protos := 0, 0
	for _, sample := range wiresharkSamples(t) {
		if sample.Group == "protos" {
			protos++
		}
		if !sample.Quick {
			continue
		}
		quick++
		t.Run(sample.Name, func(t *testing.T) {
			path := filepath.Join(wiresharkFixtureDir, wiresharkCaptureName(sample.Name))
			if sample.Sampled {
				path = strings.TrimSuffix(path, ".bin") + ".quick.bin"
				sample.CaptureSHA256 = sample.QuickSHA256
			}
			wiresharkVerifyCapture(t, path, sample)
			out := t.TempDir()
			if packets := ultimateRun(t, path, out, 1, 0); packets < 1 {
				t.Fatalf("processed %d packets", packets)
			}
			if sample.Record != "" {
				counts, _ := ultimateRecords(t, out)
				if counts[sample.Record] == 0 {
					t.Errorf("no %s records produced", sample.Record)
				}
			}
		})
	}
	if protos != 9 || quick < 5 {
		t.Fatalf("manifest has %d PROTOS samples and %d quick samples; want 9 and at least 5", protos, quick)
	}
}

// TestWiresharkCorpus runs only when the verified optional corpus is supplied.
// Each capture gets a fresh process to isolate decoder state across malformed inputs.
func TestWiresharkCorpus(t *testing.T) {
	corpus := os.Getenv("NETCAP_WIRESHARK_CORPUS")
	if corpus == "" {
		t.Skip("run make test-wireshark for the verified full corpus")
	}
	if !filepath.IsAbs(corpus) {
		corpus = filepath.Join("../..", corpus)
	}
	compatible := 0
	for _, sample := range wiresharkSamples(t) {
		if sample.Unsupported != "" {
			t.Logf("unsupported %s: %s", sample.Name, sample.Unsupported)
			continue
		}
		compatible++
		t.Run(sample.Name, func(t *testing.T) {
			path := filepath.Join(corpus, wiresharkCaptureName(sample.Name))
			wiresharkVerifyCapture(t, path, sample)
			out := t.TempDir()
			packets := ultimateRun(t, path, out, 2, 0)
			counts, _ := ultimateRecords(t, out)
			if sample.Record != "" && counts[sample.Record] == 0 {
				t.Errorf("%d packets produced no %s records", packets, sample.Record)
			}
			t.Logf("%d packets, %d audit types", packets, len(counts))
		})
	}
	if compatible < 15 {
		t.Fatalf("only %d compatible samples in manifest", compatible)
	}
}
