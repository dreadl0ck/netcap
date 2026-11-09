package file

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"io"
	"os"
	"strings"
	"testing"
)

type intermittentReader struct {
	empty  int
	source io.Reader
}

func (r *intermittentReader) Read(b []byte) (int, error) {
	if r.empty > 0 {
		r.empty--
		return 0, nil
	}
	return r.source.Read(b)
}

func TestBodyReaderToleratesBoundedEmptyReads(t *testing.T) {
	body, release, err := ReadBodyLimit(&intermittentReader{empty: 3, source: strings.NewReader("data")}, 16)
	defer release()
	if err != nil || string(body) != "data" {
		t.Fatal("valid intermittent reader rejected", err)
	}
	_, releaseStalled, err := ReadBodyLimit(&intermittentReader{empty: 1000, source: strings.NewReader("data")}, 16)
	defer releaseStalled()
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatal("unbounded reader stall", err)
	}
}

type zeroBodyReader struct{}

func (zeroBodyReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func TestDefaultExtractionSupportsReportedFTPFileSize(t *testing.T) {
	if testing.Short() {
		t.Skip("27 MiB extraction qualification")
	}
	const size = 27888036
	if decoderconfig.DefaultConfig.MaxStreamBytes < size {
		t.Fatal("default TCP limit truncates the reported FTP file")
	}
	previous := GetGlobalConfig()
	SetGlobalConfig(GetDefaultConfig())
	t.Cleanup(func() { SetGlobalConfig(previous) })
	body, release, err := ReadBody(io.LimitReader(zeroBodyReader{}, size))
	defer release()
	if err != nil || len(body) != size {
		t.Fatalf("file truncated: bytes=%d error=%v", len(body), err)
	}
}

func TestRecheckGzipBody(t *testing.T) {
	path := os.Getenv("NETCAP_RECHECK_GZIP_BODY")
	if path == "" {
		t.Skip("set NETCAP_RECHECK_GZIP_BODY to the pinned passive body")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, release, err := recoverGzipPrefix(body, 1<<20)
	if release != nil {
		defer release()
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("gzip integrity qualification missing: %v", err)
	}
	sum := sha256.Sum256(decoded)
	if len(decoded) != 7287 || hex.EncodeToString(sum[:]) != "7154dcd114db21ea999a8f841577d03d2a53ec18f589cea454cd779d29e89bc3" {
		t.Fatal("gzip evidence changed")
	}
}
