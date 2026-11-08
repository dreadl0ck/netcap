//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestAnalystInspectionAndMultiSplitCLI(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	binary := filepath.Join(temp, "net")
	env := []string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH"), "TMPDIR=" + os.Getenv("TMPDIR"), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOMAXPROCS=2", "NC_CONFIG_ROOT=" + filepath.Join(temp, "config")}
	build := exec.Command("go", "build", "-p", "1", "-tags=nodpi,noyara,nomagika", "-o", binary, "./cmd/net")
	build.Dir = root
	build.Env = env
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build %v %s", e, b)
	}
	input := filepath.Join(temp, "capture.pcap")
	writeAuditSemanticCapture(t, input)
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	original := []string{}
	var first, last int64
	for {
		packet, ci, e := reader.ReadPacketData()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		at := ci.Timestamp.UnixNano()
		if len(original) == 0 || at < first {
			first = at
		}
		if at > last {
			last = at
		}
		original = append(original, fmt.Sprintf("%d/%d/%x", at, ci.Length, packet))
	}
	if len(original) < 2 || last <= first {
		t.Fatal("insufficient capture fixture")
	}
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	t.Run("capinfos metadata", func(t *testing.T) {
		b, e := run("split", "--read", input, "--inspect")
		if e != nil {
			t.Fatalf("%v %s", e, b)
		}
		var got evidence.CaptureInspection
		if e = json.Unmarshal(b, &got); e != nil {
			t.Fatalf("%v %s", e, b)
		}
		if got.SourceSHA256 != hex.EncodeToString(hash[:]) || got.Packets != uint64(len(original)) || got.FirstNs != strconv.FormatInt(first, 10) || got.LastNs != strconv.FormatInt(last, 10) || got.Format != "pcap" {
			t.Fatalf("incorrect inspection %+v", got)
		}
	})
	t.Run("bounded partition preserves every original occurrence", func(t *testing.T) {
		out := filepath.Join(temp, "shards")
		b, e := run("split", "--read", input, "--out", out, "--start-ns", strconv.FormatInt(first, 10), "--end-ns", strconv.FormatInt(last, 10), "--shard-ns", strconv.FormatInt((last-first)/3+1, 10), "--source-sha256", hex.EncodeToString(hash[:]))
		if e != nil {
			t.Fatalf("%v %s", e, b)
		}
		var report struct {
			Shards []struct {
				File     string                  `json:"file"`
				State    string                  `json:"state"`
				Manifest evidence.PacketManifest `json:"manifest"`
			} `json:"shards"`
		}
		if e = json.Unmarshal(b, &report); e != nil {
			t.Fatalf("%v %s", e, b)
		}
		if len(report.Shards) < 2 || len(report.Shards) > 3 {
			t.Fatalf("shards %d", len(report.Shards))
		}
		selected := []string{}
		var previousEnd int64
		for i, shard := range report.Shards {
			if shard.Manifest.Selection.StartNs == nil || shard.Manifest.Selection.EndNs == nil {
				t.Fatal("missing bounds")
			}
			if i > 0 && *shard.Manifest.Selection.StartNs != previousEnd+1 {
				t.Fatal("overlapping/missing shard range")
			}
			previousEnd = *shard.Manifest.Selection.EndNs
			if shard.State == "empty-window" {
				continue
			}
			f, e := os.Open(filepath.Join(out, shard.File))
			if e != nil {
				t.Fatal(e)
			}
			ng, e := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
			if e != nil {
				t.Fatal(e)
			}
			for {
				packet, ci, e := ng.ReadPacketData()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				selected = append(selected, fmt.Sprintf("%d/%d/%x", ci.Timestamp.UnixNano(), ci.Length, packet))
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
		}
		sort.Strings(original)
		sort.Strings(selected)
		if !equalStrings(original, selected) {
			t.Fatal("partition lost/duplicated/changed packet occurrences")
		}
	})
	t.Run("overflow discards all shards", func(t *testing.T) {
		out := filepath.Join(temp, "failed")
		b, e := run("split", "--read", input, "--out", out, "--start-ns", strconv.FormatInt(first, 10), "--end-ns", strconv.FormatInt(last, 10), "--shard-ns", strconv.FormatInt((last-first)/3+1, 10), "--max-bytes", "1")
		if e == nil {
			t.Fatalf("overflow succeeded %s", b)
		}
		if _, e = os.Stat(out); !os.IsNotExist(e) {
			t.Fatal("partial partition remained")
		}
	})
	t.Run("producer identity is captured at creation", func(t *testing.T) {
		out := filepath.Join(temp, "audit")
		b, e := run("capture", "-read", input, "-out", out, "-workers", "1", "-include", "TCP", "-context=true", "-capture-evidence=true", "-dpi=false", "-geoDB=false", "-network-detection=false", "-fileStorage", "", "-http", "", "-quiet", "-y")
		if e != nil {
			t.Fatalf("%v %s", e, b)
		}
		raw, e := os.ReadFile(filepath.Join(out, "capture-manifest.json"))
		if e != nil {
			t.Fatal(e)
		}
		var manifest evidence.CaptureManifest
		if e = json.Unmarshal(raw, &manifest); e != nil {
			t.Fatal(e)
		}
		if manifest.Producer == nil || manifest.Producer.Version == "" || manifest.Producer.GoVersion == "" || manifest.InputSHA256 != hex.EncodeToString(hash[:]) {
			t.Fatalf("missing producer/source identity %+v", manifest)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
