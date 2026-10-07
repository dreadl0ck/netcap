package collector

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/flowexport"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type bookExportFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type bookExportRecord struct {
	File             string          `json:"file"`
	FileSHA256       string          `json:"fileSHA256"`
	Type             string          `json:"type"`
	Ordinal          uint64          `json:"ordinal"`
	TimestampNs      string          `json:"timestampNs"`
	RecordSHA256     string          `json:"recordSHA256"`
	ObservationID    string          `json:"observationId,omitempty"`
	SnapshotSequence uint64          `json:"snapshotSequence,omitempty"`
	Record           json.RawMessage `json:"record"`
	ContentPaths     []string        `json:"contentPaths,omitempty"`
}
type bookExportOracle struct {
	Version                  int                `json:"version"`
	Case                     string             `json:"case"`
	Status                   string             `json:"status"`
	Synthetic                bool               `json:"synthetic"`
	RunID                    string             `json:"runId"`
	InputSHA256              string             `json:"inputSHA256"`
	Workers                  int                `json:"workers"`
	StrictChecksums          bool               `json:"strictChecksums"`
	OriginalOutput           string             `json:"originalOutput"`
	RecordHashEncoding       string             `json:"recordHashEncoding"`
	OrdinalBase              int                `json:"ordinalBase"`
	FlowExportTimestampBasis string             `json:"flowExportTimestampBasis"`
	Files                    []bookExportFile   `json:"files"`
	Records                  []bookExportRecord `json:"records"`
	Packets                  []bookExportPacket `json:"packets"`
}

type bookExportPacket struct {
	Ordinal       uint64 `json:"ordinal"`
	TimestampNs   string `json:"timestampNs"`
	CapturedBytes int    `json:"capturedBytes"`
	WireBytes     int    `json:"wireBytes"`
	SHA256        string `json:"sha256"`
	SrcIP         string `json:"srcIP,omitempty"`
	DstIP         string `json:"dstIP,omitempty"`
	SrcPort       string `json:"srcPort,omitempty"`
	DstPort       string `json:"dstPort,omitempty"`
}

func bookPacketOracle(t *testing.T, input string) []bookExportPacket {
	t.Helper()
	var reader interface {
		ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	}
	var file *os.File
	var err error
	if strings.HasSuffix(input, ".pcapng") {
		reader, file, err = openPcapNG(input)
	} else {
		reader, file, err = OpenPCAP(input)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var packets []bookExportPacket
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		r := bookExportPacket{Ordinal: uint64(len(packets)), TimestampNs: fmt.Sprint(ci.Timestamp.UnixNano()), CapturedBytes: ci.CaptureLength, WireBytes: ci.Length, SHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
		if n := p.NetworkLayer(); n != nil {
			r.SrcIP, r.DstIP = n.NetworkFlow().Src().String(), n.NetworkFlow().Dst().String()
		}
		if n := p.TransportLayer(); n != nil {
			r.SrcPort, r.DstPort = n.TransportFlow().Src().String(), n.TransportFlow().Dst().String()
		}
		packets = append(packets, r)
	}
	return packets
}

func exportBookCase(t *testing.T, input, out string, workers int, strict bool) {
	t.Helper()
	root := os.Getenv("NETCAP_BOOK_EXPORT_DIR")
	if !filepath.IsAbs(root) {
		t.Fatal("NETCAP_BOOK_EXPORT_DIR must be absolute")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	m := bookJSON[evidence.CaptureManifest](t, filepath.Join(out, "capture-manifest.json"))
	name := strings.NewReplacer("/", "--", "=", "-").Replace(t.Name()) + "--" + m.RunID
	dir, err := os.MkdirTemp(root, ".pending-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	oracle := bookExportOracle{Version: 1, Case: t.Name(), Status: "passed", Synthetic: true, RunID: m.RunID, InputSHA256: m.InputSHA256, Workers: workers, StrictChecksums: strict, OriginalOutput: out, RecordHashEncoding: "compact-json", FlowExportTimestampBasis: "received-ns"}
	oracle.Packets = bookPacketOracle(t, input)
	copyFile := func(src, rel string) {
		t.Helper()
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0400); err != nil {
			t.Fatal(err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(data))
		oracle.Files = append(oracle.Files, bookExportFile{rel, digest, int64(len(data))})
		if filepath.Base(rel) == "FlowExports.jsonl" {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			scanner.Buffer(make([]byte, 4096), 2<<20)
			for ordinal := uint64(0); scanner.Scan(); ordinal++ {
				line := append([]byte(nil), scanner.Bytes()...)
				var event flowexport.Event
				if err := json.Unmarshal(line, &event); err != nil {
					t.Fatal(err)
				}
				ref := bookExportRecord{File: rel, FileSHA256: digest, Type: "FlowExport/" + event.Kind, Ordinal: ordinal, RecordSHA256: fmt.Sprintf("%x", sha256.Sum256(line)), Record: line}
				if event.Observation != nil {
					ref.ObservationID = event.Observation.ID
					ref.TimestampNs = fmt.Sprint(event.Observation.Envelope.ReceivedNs)
				} else if event.Envelope != nil {
					ref.TimestampNs = fmt.Sprint(event.Envelope.ReceivedNs)
				} else if event.Issue != nil {
					ref.TimestampNs = fmt.Sprint(event.Issue.Envelope.ReceivedNs)
				}
				oracle.Records = append(oracle.Records, ref)
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			return
		}
		if !strings.HasSuffix(rel, ".ncap") && !strings.HasSuffix(rel, ".ncap.gz") {
			return
		}
		r, err := netio.Open(src, 4096)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		h, err := r.ReadHeader()
		if err != nil {
			t.Fatal(err)
		}
		for ordinal := uint64(0); ; ordinal++ {
			record := netio.InitRecord(h.Type)
			if record == nil {
				t.Fatalf("unsupported export type: %v", h.Type)
			}
			if err := r.Next(record); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			audit := record.(types.AuditRecord)
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			ref := bookExportRecord{File: rel, FileSHA256: digest, Type: strings.TrimPrefix(h.Type.String(), "NC_"), Ordinal: ordinal, TimestampNs: fmt.Sprint(audit.Time()), RecordSHA256: fmt.Sprintf("%x", sha256.Sum256(encoded)), Record: encoded}
			if c, ok := record.(*types.Connection); ok {
				ref.ObservationID = c.ObservationID
				ref.SnapshotSequence = c.SnapshotSequence
			}
			oracle.Records = append(oracle.Records, ref)
		}
	}
	copyFile(input, "input"+filepath.Ext(input))
	if oracle.Files[0].SHA256 != m.InputSHA256 {
		t.Fatal("export input differs from capture provenance")
	}
	if err := filepath.WalkDir(out, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected symlink in qualification output")
		}
		if e.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(rel, ".log") {
			return nil
		}
		copyFile(path, filepath.Join("audit", rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// File.Location preserves the producer's path, including after sensor import.
	// Locate portable artifact copies by content identity without rewriting audits.
	for i := range oracle.Records {
		r := &oracle.Records[i]
		if r.Type != "File" {
			continue
		}
		var record types.File
		if err := json.Unmarshal(r.Record, &record); err != nil {
			t.Fatal(err)
		}
		if record.Hashes != nil && record.Hashes.SHA256 != "" {
			for _, file := range oracle.Files {
				if file.SHA256 == record.Hashes.SHA256 {
					r.ContentPaths = append(r.ContentPaths, file.Path)
				}
			}
		}
	}
	encoded, err := json.MarshalIndent(oracle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oracle.json"), encoded, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oracle.sha256"), []byte(fmt.Sprintf("%x  oracle.json\n", sha256.Sum256(encoded))), 0400); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return os.Chmod(path, 0500)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, name)
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("qualification export must never replace an existing case")
	}
	if err := os.Rename(dir, target); err != nil {
		t.Fatal(err)
	}
	t.Logf("qualification artifacts: %s", target)
}

func TestBookExportIntegrity(t *testing.T) {
	if root := os.Getenv("NETCAP_BOOK_VERIFY_DIR"); root != "" {
		paths, err := filepath.Glob(filepath.Join(root, "*", "oracle.json"))
		if err != nil || len(paths) == 0 {
			t.Fatal("no exported oracles to verify")
		}
		for _, path := range paths {
			t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) { verifyBookExport(t, path) })
		}
		return
	}
	t.Setenv("NETCAP_BOOK_EXPORT_DIR", "")
	b, input := newBookCapture(t)
	b.conversation("192.0.2.1", "198.51.100.1", 61005, 80, false, bookMessage{false, "GET /export HTTP/1.1\r\nHost: lab.invalid\r\n\r\n"}, bookMessage{true, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nLAB!"})
	out := runBookCase(t, input, 1, false)
	root := t.TempDir()
	t.Setenv("NETCAP_BOOK_EXPORT_DIR", root)
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
			if err == nil && e.IsDir() {
				return os.Chmod(path, 0700)
			}
			return err
		})
	})
	exportBookCase(t, input, out, 1, false)
	paths, err := filepath.Glob(filepath.Join(root, "*", "oracle.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("missing oracle")
	}
	verifyBookExport(t, paths[0])
}

func verifyBookExport(t *testing.T, path string) {
	t.Helper()
	oracle := bookJSON[bookExportOracle](t, path)
	if len(oracle.Records) == 0 || len(oracle.Packets) == 0 || oracle.OrdinalBase != 0 || oracle.RecordHashEncoding != "compact-json" {
		t.Fatal("incomplete export indexes")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := os.ReadFile(filepath.Join(filepath.Dir(path), "oracle.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if string(digest) != fmt.Sprintf("%x  oracle.json\n", sha256.Sum256(data)) {
		t.Fatal("oracle digest mismatch")
	}
	files := map[string]string{}
	for _, f := range oracle.Files {
		if !filepath.IsLocal(f.Path) {
			t.Fatal("export inventory path escapes root")
		}
		p := filepath.Join(filepath.Dir(path), f.Path)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0400 || int64(len(b)) != f.Bytes || fmt.Sprintf("%x", sha256.Sum256(b)) != f.SHA256 {
			t.Fatal("export is mutable or changed bytes")
		}
		files[f.Path] = f.SHA256
	}
	capture := bookJSON[evidence.CaptureManifest](t, filepath.Join(filepath.Dir(path), "audit", "capture-manifest.json"))
	if oracle.InputSHA256 != capture.InputSHA256 || uint64(len(oracle.Packets)) != capture.IngressPackets {
		t.Fatal("packet oracle/capture scope mismatch")
	}
	for i, p := range oracle.Packets {
		if p.Ordinal != uint64(i) || p.TimestampNs == "" || len(p.SHA256) != 64 {
			t.Fatal("invalid packet oracle reference")
		}
	}
	ordinals := map[string]uint64{}
	for _, r := range oracle.Records {
		var compact bytes.Buffer
		if err := json.Compact(&compact, r.Record); err != nil {
			t.Fatal(err)
		}
		if files[r.File] != r.FileSHA256 || fmt.Sprintf("%x", sha256.Sum256(compact.Bytes())) != r.RecordSHA256 || r.Ordinal != ordinals[r.File] || r.TimestampNs == "" {
			t.Fatalf("invalid exported reference: %+v", r)
		}
		ordinals[r.File]++
		if r.Type == "File" {
			var f types.File
			if err := json.Unmarshal(r.Record, &f); err != nil {
				t.Fatal(err)
			}
			if f.Hashes != nil && f.Hashes.SHA256 != "" {
				if len(r.ContentPaths) == 0 {
					t.Fatal("extracted artifact has no portable content path")
				}
				for _, p := range r.ContentPaths {
					if files[p] != f.Hashes.SHA256 {
						t.Fatal("artifact path hash mismatch")
					}
				}
			}
		}
	}
}
