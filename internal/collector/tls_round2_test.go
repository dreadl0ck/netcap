package collector

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/gogo/protobuf/proto"
)

func TestTLSRound2Corpus(t *testing.T) {
	if os.Getenv("NETCAP_TLS_CORPUS") != "1" {
		t.Skip("set NETCAP_TLS_CORPUS=1 to fetch the pinned, size/hash-checked small Zeek/Suricata fixtures")
	}
	var manifest struct {
		Source  string
		Samples []struct {
			Path, SHA256, Format, ServerFormat, Source string
			Size, Client, Server                       int
			ClientHello, ServerHello                   map[string]any
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
			source := manifest.Source
			if sample.Source != "" {
				source = sample.Source
			}
			resp, err := client.Get(source + sample.Path)
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
						format := sample.Format
						expect := sample.ClientHello
						if name == "TLSServerHello" && sample.ServerFormat != "" {
							format = sample.ServerFormat
						}
						if name == "TLSServerHello" {
							expect = sample.ServerHello
						}
						current[name] = tlsRound2Records(t, path, format, expect, os.Getenv("NETCAP_TLS_BASELINE") == "1")
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

func tlsRound2Records(t *testing.T, path, format string, expect map[string]any, baseline bool) []string {
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
			for key, want := range expect {
				got := fields[key]
				if strings.HasSuffix(key, "Hex") {
					encoded, _ := fields[strings.TrimSuffix(key, "Hex")].(string)
					b, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					got = hex.EncodeToString(b)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: got %v want %v", key, got, want)
				}
			}
			if fields["HelloFormat"] != format || fields["CommunityID"] == nil || fields["SrcIP"] == nil || fields["DstIP"] == nil || fields["SrcPort"] == nil || fields["DstPort"] == nil || fields["Timestamp"] == nil {
				t.Fatal("missing protocol/flow/time metadata", fields)
			}
			if format == "SSLv2" && (fields["Ja4"] != nil || fields["Ja4s"] != nil || fields["SSLv2CipherSpecs"] == nil || fields["CipherSuites"] != nil || fields["CipherSuite"] != nil || fields["Random"] != nil) {
				t.Fatal("fabricated TLS fingerprint or missing 24-bit cipher specs", fields)
			}
		}
	}
	sort.Strings(hashes)
	return hashes
}
