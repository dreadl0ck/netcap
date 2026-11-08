// Package analyst implements finite, explicitly included capture investigations.
package analyst

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/proto"
)

const MaxRecords = 100000
const MaxDecodedBytes int64 = 128 << 20

var ErrStale = errors.New("analyst evidence binding is stale")

type Binding struct {
	RunID          string `json:"runId"`
	SourceSHA256   string `json:"sourceSHA256"`
	ManifestSHA256 string `json:"manifestSHA256"`
}

type Reference struct {
	Version      int     `json:"version"`
	Binding      Binding `json:"binding"`
	Type         string  `json:"type"`
	File         string  `json:"file"`
	FileSHA256   string  `json:"fileSHA256"`
	Ordinal      string  `json:"ordinal"`
	RecordSHA256 string  `json:"recordSHA256"`
	TimestampNs  string  `json:"timestampNs"`
}

func Digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func IsHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}

func Bind(ctx context.Context, dir string) (Binding, error) {
	return bind(ctx, dir, true)
}
func BindDiagnostic(ctx context.Context, dir string) (Binding, error) { return bind(ctx, dir, false) }
func bind(ctx context.Context, dir string, readyRequired bool) (Binding, error) {
	var b Binding
	data, err := artifactio.Read(ctx, dir, "capture-manifest.json", 4<<20)
	if err != nil {
		return b, err
	}
	var m evidence.CaptureManifest
	if err = json.Unmarshal(data, &m); err != nil {
		return b, err
	}
	if m.Version != 1 || m.RunID == "" || len(m.RunID) > 128 || !IsHash(m.InputSHA256) {
		return b, fmt.Errorf("file-capture provenance required")
	}
	if !readyRequired {
		return Binding{m.RunID, m.InputSHA256, Digest(data)}, nil
	}
	if (m.Status != "done" && m.Status != "complete") || m.Error != "" {
		return b, fmt.Errorf("finalized capture required")
	}
	ready, err := artifactio.Read(ctx, dir, evidence.AuditReadyFile, 4096)
	if err != nil {
		return b, err
	}
	var marker struct {
		Version int    `json:"version"`
		RunID   string `json:"runId"`
	}
	if json.Unmarshal(ready, &marker) != nil || marker.Version != 1 || marker.RunID != m.RunID {
		return b, fmt.Errorf("audit readiness does not match capture")
	}
	return Binding{m.RunID, m.InputSHA256, Digest(data)}, nil
}

func CheckDiagnostic(ctx context.Context, dir string, expected Binding) error {
	if expected.RunID == "" || !IsHash(expected.SourceSHA256) || !IsHash(expected.ManifestSHA256) {
		return fmt.Errorf("complete diagnostic binding required")
	}
	got, err := BindDiagnostic(ctx, dir)
	if err != nil {
		return err
	}
	if got != expected {
		return ErrStale
	}
	return nil
}

func Check(ctx context.Context, dir string, expected Binding) error {
	if expected.RunID == "" || !IsHash(expected.SourceSHA256) || !IsHash(expected.ManifestSHA256) {
		return fmt.Errorf("complete capture binding required")
	}
	got, err := Bind(ctx, dir)
	if err != nil {
		return err
	}
	if got != expected {
		return ErrStale
	}
	return nil
}

type budgetReader struct {
	ctx       context.Context
	input     io.Reader
	remaining int64
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		var b [1]byte
		n, e := r.input.Read(b[:])
		if n > 0 {
			return 0, fmt.Errorf("decoded audit byte limit exceeded")
		}
		return 0, e
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, e := r.input.Read(p)
	r.remaining -= int64(n)
	return n, e
}

// Walk hashes the stored audit file and each original protobuf frame. A callback
// result must not be published until Walk succeeds and file/generation checks finish.
func Walk(ctx context.Context, dir string, binding Binding, recordType string, visit func(Reference, proto.Message) error) error {
	return walk(ctx, dir, binding, recordType, visit, nil)
}
func Scan(ctx context.Context, dir string, binding Binding, recordType string, visit func(Reference, proto.Message) error) (string, error) {
	var digest string
	err := walk(ctx, dir, binding, recordType, visit, &digest)
	return digest, err
}
func walk(ctx context.Context, dir string, binding Binding, recordType string, visit func(Reference, proto.Message) error, fileDigest *string) error {
	if err := Check(ctx, dir, binding); err != nil {
		return err
	}
	typeID, ok := types.Type_value["NC_"+recordType]
	if !ok || netio.InitRecord(types.Type(typeID)) == nil {
		return fmt.Errorf("unsupported audit type")
	}
	name := recordType + ".ncap.gz"
	f, info, err := artifactio.Open(dir, name)
	if errors.Is(err, os.ErrNotExist) {
		name = recordType + ".ncap"
		f, info, err = artifactio.Open(dir, name)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if info.Size() > 64<<20 {
		return fmt.Errorf("stored audit byte limit exceeded")
	}
	// Hash a pinned descriptor before decoding; verify it again afterwards.
	h := sha256.New()
	if _, err = io.Copy(h, &budgetReader{ctx, f, 64 << 20}); err != nil {
		return err
	}
	fileHash := hex.EncodeToString(h.Sum(nil))
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var input io.Reader = f
	if strings.HasSuffix(name, ".gz") {
		z, e := gzip.NewReader(f)
		if e != nil {
			return e
		}
		defer z.Close()
		input = z
	}
	r := delimited.NewReaderWithLimit(&budgetReader{ctx, input, MaxDecodedBytes}, 4<<20)
	var header types.Header
	if err = r.NextProto(&header); err != nil {
		return err
	}
	if header.Type != types.Type(typeID) {
		return fmt.Errorf("audit header type mismatch")
	}
	for ordinal := 0; ; ordinal++ {
		raw, e := r.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if ordinal >= MaxRecords {
			return fmt.Errorf("audit record limit exceeded")
		}
		msg := netio.InitRecord(header.Type)
		if e = proto.Unmarshal(raw, msg); e != nil {
			return e
		}
		at := "0"
		if ar, ok := msg.(types.AuditRecord); ok {
			at = strconv.FormatInt(ar.Time(), 10)
		}
		ref := Reference{1, binding, recordType, name, fileHash, strconv.Itoa(ordinal), Digest(raw), at}
		if e = visit(ref, msg); e != nil {
			return e
		}
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return ErrStale
	}
	current, _, err := artifactio.Open(dir, name)
	if err != nil {
		return err
	}
	defer current.Close()
	ci, err := current.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, ci) {
		return ErrStale
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	h.Reset()
	if _, err = io.Copy(h, &budgetReader{ctx, f, 64 << 20}); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != fileHash {
		return ErrStale
	}
	if err := Check(ctx, dir, binding); err != nil {
		return err
	}
	if fileDigest != nil {
		*fileDigest = fileHash
	}
	return nil
}

func Resolve(ctx context.Context, dir string, ref Reference) (json.RawMessage, error) {
	if ref.Version != 1 || !IsHash(ref.FileSHA256) || !IsHash(ref.RecordSHA256) {
		return nil, fmt.Errorf("invalid occurrence reference")
	}
	var result json.RawMessage
	err := Walk(ctx, dir, ref.Binding, ref.Type, func(got Reference, msg proto.Message) error {
		if got.Ordinal != ref.Ordinal {
			return nil
		}
		if got != ref {
			return ErrStale
		}
		text, e := RecordJSON(msg)
		if e != nil {
			return e
		}
		result = text
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrStale
	}
	return result, nil
}

func RecordJSON(msg proto.Message) (json.RawMessage, error) {
	text, err := (&jsonpb.Marshaler{OrigName: true}).MarshalToString(msg)
	return json.RawMessage(text), err
}
