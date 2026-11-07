package collector

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/gogo/protobuf/proto"
)

func TestTLSRound2Corpus(t *testing.T) {
	if os.Getenv("NETCAP_TLS_CORPUS") != "1" {
		t.Skip("set NETCAP_TLS_CORPUS=1 to fetch the pinned, size/hash-checked small Zeek fixtures")
	}
	var manifest struct {
		Source  string
		Samples []struct {
			Path, SHA256, Format string
			Size, Client, Server int
		}
	}
	manifestPath := os.Getenv("NETCAP_TLS_MANIFEST")
	if manifestPath == "" {
		manifestPath = "../decoder/stream/tls/testdata/round2.json"
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 45 * time.Second}
	for _, sample := range manifest.Samples {
		t.Run(sample.Path, func(t *testing.T) {
			resp, err := client.Get(manifest.Source + sample.Path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(io.LimitReader(resp.Body, int64(sample.Size)+1))
			if err != nil || resp.StatusCode != http.StatusOK || len(b) != sample.Size || fmt.Sprintf("%x", sha256.Sum256(b)) != sample.SHA256 {
				t.Fatalf("fixture integrity: status=%d bytes=%d error=%v", resp.StatusCode, len(b), err)
			}
			input := filepath.Join(t.TempDir(), "input.pcap")
			if err := os.WriteFile(input, b, 0600); err != nil {
				t.Fatal(err)
			}
			var previous map[string][]string
			for _, workers := range []int{1, 2} {
				out := t.TempDir()
				packets := ultimateRun(t, input, out, workers, 1000)
				current := map[string][]string{}
				for name, want := range map[string]int{"TLSClientHello": sample.Client, "TLSServerHello": sample.Server} {
					path := filepath.Join(out, name+".ncap")
					if _, err := os.Stat(path); err == nil {
						current[name] = tlsRound2Records(t, path, sample.Format, os.Getenv("NETCAP_TLS_BASELINE") == "1")
					}
					t.Logf("workers=%d packets=%d %s=%d expected=%d sha256=%s", workers, packets, name, len(current[name]), want, sample.SHA256)
					if os.Getenv("NETCAP_TLS_BASELINE") != "1" && len(current[name]) != want {
						t.Errorf("%s: got %d want %d", name, len(current[name]), want)
					}
				}
				if previous != nil && !reflect.DeepEqual(previous, current) {
					t.Fatal("TLS record content depends on worker count")
				}
				previous = current
			}
		})
	}
}

func tlsRound2Records(t *testing.T, path, format string, baseline bool) []string {
	t.Helper()
	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	header, err := r.ReadHeader()
	if err != nil {
		t.Fatal(err)
	}
	var hashes []string
	for {
		record := netio.InitRecord(header.Type).(proto.Message)
		if err := r.Next(record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		b, err := proto.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, fmt.Sprintf("%x", sha256.Sum256(b)))
		// Reflection keeps this replay harness buildable on the unmodified W76 base.
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if !baseline {
			if fields["HelloFormat"] != format || fields["CommunityID"] == nil || fields["SrcIP"] == nil || fields["Timestamp"] == nil {
				t.Fatal("missing protocol/flow/time metadata", fields)
			}
			if format == "SSLv2" && (fields["Ja4"] != nil || fields["Ja4s"] != nil || fields["SSLv2CipherSpecs"] == nil) {
				t.Fatal("fabricated TLS fingerprint or missing 24-bit cipher specs", fields)
			}
		}
	}
	sort.Strings(hashes)
	return hashes
}
