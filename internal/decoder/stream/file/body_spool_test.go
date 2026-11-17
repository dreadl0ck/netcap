package file

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

func spoolTestConfig(t *testing.T) *Config {
	t.Helper()
	old, oldDecoder := GetGlobalConfig(), decoderconfig.Instance
	cfg := GetDefaultConfig()
	SetGlobalConfig(cfg)
	decoderconfig.Instance = &decoderconfig.Config{Out: t.TempDir(), FileStorage: "files"}
	t.Cleanup(func() { SetGlobalConfig(old); decoderconfig.Instance = oldDecoder; ResetDedupCache() })
	return cfg
}

func TestSpoolAnalysisMatchesBytes(t *testing.T) {
	spoolTestConfig(t)
	pe := make([]byte, 40000)
	copy(pe, "MZ")
	pe[60] = 0x00
	pe[61] = 0x90
	copy(pe[0x9000:], "PE\x00\x00")
	cases := [][]byte{nil, []byte("x"), []byte("#!"), []byte("ordinary text"), pe, append([]byte{0xd0, 0xcf, 0x11, 0xe0}, []byte(strings.Repeat("x", 32760)+"EncryptedPackage")...), []byte("{" + strings.Repeat(" ", 40000) + ":1}"), []byte("#!" + strings.Repeat("x", 32763) + "python\nvar x"), []byte("#!unknown\n" + strings.Repeat("x", 32760) + "python")}
	for _, token := range append(append([]string(nil), artifactTokens...), "PoWeRsHeLl", "Sub Auto", "document.write(") {
		cases = append(cases, []byte(strings.Repeat("x", 32766)+token))
	}
	for i, data := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			spool, err := SpoolBody(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			got, err := spool.content.Analyze("fixture.exe")
			if err != nil {
				t.Fatal(err)
			}
			want := AnalyzeFile(data, "fixture.exe")
			if math.Abs(got.Entropy-want.Entropy) > 1e-12 {
				t.Fatalf("entropy %v != %v", got.Entropy, want.Entropy)
			}
			got.Entropy = want.Entropy
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("analysis mismatch: got %+v want %+v", got, want)
			}
			mime, accurate := DetectContentType(data)
			gm, ga := spool.content.Detect()
			if gm != mime || ga != accurate {
				t.Fatalf("MIME %s/%v != %s/%v", gm, ga, mime, accurate)
			}
			hashes, err := spool.content.Hashes()
			if err != nil || hashes != ComputeHashes(data) {
				t.Fatal("hash mismatch", hashes, err)
			}
		})
	}
}

func TestSpoolLimitsAndCleanup(t *testing.T) {
	cfg := spoolTestConfig(t)
	cfg.FileExtraction.SizeLimits.MaxFileSize = 100
	cfg.FileExtraction.SizeLimits.MaxScratchBytes = 150
	SetGlobalConfig(cfg)
	for _, n := range []int{99, 100, 101} {
		spool, err := SpoolBody(strings.NewReader(strings.Repeat("x", n)))
		if (n > 100) != errors.Is(err, ErrArtifactLimit) {
			t.Fatalf("length %d: %v", n, err)
		}
		if spool == nil || spool.Size() != int64(min(n, 100)) {
			t.Fatal("partial body lost")
		}
		name := spool.content.file.Name()
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("scratch file retained", err)
		}
	}
	first, err := SpoolBody(strings.NewReader(strings.Repeat("a", 100)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := SpoolBody(strings.NewReader(strings.Repeat("b", 100)))
	if !errors.Is(err, ErrArtifactLimit) {
		t.Fatal("shared scratch cap ignored", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	artifactScratch.Lock()
	used := artifactScratch.used
	artifactScratch.Unlock()
	if used != 0 {
		t.Fatal("scratch credits leaked", used)
	}
	resetExtractionBudget(true)
	defer resetExtractionBudget(false)
	extractionBudget.Lock()
	extractionBudget.limit = artifactScanMemory - 1
	extractionBudget.Unlock()
	if spool, err := SpoolBody(strings.NewReader("x")); spool != nil || !errors.Is(err, ErrArtifactLimit) {
		t.Fatal("scratch analysis allocation was not admitted", err)
	}
}

func TestSpoolDecodedOutputMatchesByteOutput(t *testing.T) {
	spoolTestConfig(t)
	oldWriter, oldCount := Decoder.Writer, Decoder.NumRecordsWritten
	t.Cleanup(func() { Decoder.Writer, Decoder.NumRecordsWritten = oldWriter, oldCount })
	w := &savedFileWriter{}
	Decoder.Writer = w
	body := []byte(strings.Repeat("bounded artifact fixture\n", 4000))
	conv := &core.ConversationInfo{Ident: "spool-fixture", FirstClientPacket: time.Unix(10, 0)}
	for _, kind := range []string{"identity", "gzip", "br", "zlib", "raw-deflate", "base64", "stacked"} {
		t.Run(kind, func(t *testing.T) {
			wire := body
			encoding := []string{kind}
			switch kind {
			case "gzip", "br", "zlib", "raw-deflate":
				wire = encodedFixture(t, body, kind)
				if kind == "zlib" || kind == "raw-deflate" {
					encoding = []string{"deflate"}
				}
			case "base64":
				wire = []byte(base64.StdEncoding.EncodeToString(body))
			case "stacked":
				wire = []byte(base64.StdEncoding.EncodeToString(encodedFixture(t, body, "gzip")))
				encoding = []string{"gzip", "base64"}
			}
			spool, err := SpoolBody(bytes.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			before := len(w.records)
			if err := SaveSpoolEnhanced(conv, "HTTP", "fixture.txt", nil, spool, encoding, "fixture.test", "text/plain", 0, "", "server_to_client", "HTTP"); err != nil {
				t.Fatal(err)
			}
			if len(w.records) != before+1 {
				t.Fatal("missing file observation")
			}
			record := w.records[before]
			got, err := os.ReadFile(record.Location)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("stored body differs", err)
			}
			if record.Hash != ComputeHashes(body).MD5 {
				t.Fatal("decoded hash differs", record.Hash)
			}
		})
	}
}

type spoolErrorReader struct{ err error }

func (r spoolErrorReader) Read([]byte) (int, error) { return 0, r.err }

type spoolPanicReader struct{}

func (spoolPanicReader) Read([]byte) (int, error) { panic("spool control") }

func TestSpoolReadFailuresRetainPrefixAndReleaseScratch(t *testing.T) {
	spoolTestConfig(t)
	for _, err := range []error{io.ErrUnexpectedEOF, errors.New("body read failure"), nil} {
		reader := io.MultiReader(strings.NewReader("retained prefix"), spoolErrorReader{err})
		spool, got := SpoolBody(reader)
		if err == nil {
			err = io.ErrNoProgress
		}
		if !errors.Is(got, err) || spool == nil || spool.Size() != 15 {
			t.Fatal("read failure lost partial evidence", got)
		}
		if err := spool.Close(); err != nil {
			t.Fatal(err)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic control did not run")
			}
		}()
		_, _ = SpoolBody(io.MultiReader(strings.NewReader("partial"), spoolPanicReader{}))
	}()
	artifactScratch.Lock()
	used := artifactScratch.used
	artifactScratch.Unlock()
	if used != 0 {
		t.Fatal("panic retained scratch credits", used)
	}
	entries, err := os.ReadDir(filepath.Join(decoderconfig.Instance.Out, ".artifact-scratch"))
	if err != nil || len(entries) != 0 {
		t.Fatal("panic retained scratch files", entries, err)
	}
}
