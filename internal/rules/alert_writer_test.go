package rules

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
)

func openAlertWriter(t *testing.T, dir string) *FileAlertWriter {
	t.Helper()
	w, err := NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func readAlertHistory(t *testing.T, dir string) []*types.Alert {
	t.Helper()
	r, err := netio.Open(filepath.Join(dir, "Alert.ncap.gz"), defaults.BufferSize)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h, err := r.ReadHeader()
	if err != nil || h.Type != types.Type_NC_Alert {
		t.Fatalf("header = %v, error = %v", h, err)
	}
	var alerts []*types.Alert
	for {
		a := new(types.Alert)
		err := r.Next(a)
		if err == io.EOF {
			return alerts
		}
		if err != nil {
			t.Fatal(err)
		}
		alerts = append(alerts, a)
	}
}

func TestFileAlertWriterVisibleBeforeCloseAndAppend(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	first := &types.Alert{Name: "first", Timestamp: 123, MatchedRecord: `{"DstPort":22}`}
	if err := w.WriteAlert(first); err != nil {
		t.Fatal(err)
	}
	if got := readAlertHistory(t, dir); len(got) != 1 || !proto.Equal(got[0], first) {
		t.Fatalf("live alerts = %v", got)
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	prefix, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w = openAlertWriter(t, dir)
	if err := w.WriteAlert(&types.Alert{Name: "second"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(data, prefix) || len(data) <= len(prefix) {
		t.Fatalf("history was rewritten or not appended: %v", err)
	}
	if got := readAlertHistory(t, dir); len(got) != 2 || got[1].Name != "second" {
		t.Fatalf("appended alerts = %v", got)
	}
}

func alertFixture(t *testing.T, typ types.Type) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	d := delimited.NewWriter(g)
	for _, msg := range []proto.Message{&types.Header{Type: typ, Version: "legacy"}, &types.Alert{Name: "legacy"}} {
		if err := d.PutProto(msg); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestFileAlertWriterLegacyHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Alert.ncap.gz")
	legacy := alertFixture(t, types.Type_NC_Alert)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	w := openAlertWriter(t, dir)
	if err := w.WriteAlert(&types.Alert{Name: "new"}); err != nil {
		t.Fatal(err)
	}
	if got := readAlertHistory(t, dir); len(got) != 2 || got[0].Name != "legacy" || got[1].Name != "new" {
		t.Fatalf("alerts = %v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(data, legacy) {
		t.Fatalf("legacy bytes changed: %v", err)
	}
}

func TestFileAlertWriterRejectsCorruptHistoryWithoutChangingIt(t *testing.T) {
	valid := alertFixture(t, types.Type_NC_Alert)
	badChecksum := bytes.Clone(valid)
	badChecksum[len(badChecksum)-8] ^= 0xff
	var oversized bytes.Buffer
	g := gzip.NewWriter(&oversized)
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], maxAlertRecordSize+1)
	_, _ = g.Write(prefix[:n])
	_ = g.Close()
	for name, data := range map[string][]byte{
		"empty": {}, "not-gzip": []byte("bad"), "truncated": valid[:len(valid)-4],
		"checksum": badChecksum, "wrong-type": alertFixture(t, types.Type_NC_TCP),
		"oversized": oversized.Bytes(), "partial-member": append(bytes.Clone(valid), 0x1f),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "Alert.ncap.gz")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			w, err := NewFileAlertWriter(dir)
			if err == nil {
				_ = w.Close()
				t.Fatal("accepted corrupt history")
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("history changed: %v", err)
			}
		})
	}
}

func TestFileAlertWriterLifecycle(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	if err := w.WriteAlert(nil); err == nil {
		t.Fatal("accepted nil alert")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteAlert(&types.Alert{}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "Alert.ncap.gz")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty writer created a file: %v", err)
	}
}

func TestFileAlertWriterConcurrentJobs(t *testing.T) {
	dir := t.TempDir()
	writers := []*FileAlertWriter{openAlertWriter(t, dir), openAlertWriter(t, dir)}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := writers[i%2].WriteAlert(&types.Alert{Name: fmt.Sprintf("alert-%d", i)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := writers[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := writers[1].WriteAlert(&types.Alert{Name: "after-peer-close"}); err != nil {
		t.Fatal(err)
	}
	got := readAlertHistory(t, dir)
	seen := make(map[string]bool)
	for _, a := range got {
		if seen[a.Name] {
			t.Fatalf("duplicate alert %s", a.Name)
		}
		seen[a.Name] = true
	}
	if len(got) != 33 {
		t.Fatalf("got %d alerts", len(got))
	}
}

var errAlertDisk = errors.New("injected alert disk failure")

type failingAlertFile struct {
	alertFile
	partial bool
	short   bool
	syncErr bool
}

func (f *failingAlertFile) Write(data []byte) (int, error) {
	if f.partial || f.short {
		n, _ := f.alertFile.Write(data[:len(data)/2])
		if f.short {
			return n, nil
		}
		return n, errAlertDisk
	}
	return f.alertFile.Write(data)
}

func (f *failingAlertFile) Sync() error {
	if f.syncErr {
		f.syncErr = false
		return errAlertDisk
	}
	return f.alertFile.Sync()
}

func TestFileAlertWriterPersistenceFailure(t *testing.T) {
	for _, mode := range []string{"partial-write", "short-write", "sync"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			w := openAlertWriter(t, dir)
			if err := w.WriteAlert(&types.Alert{Name: "committed"}); err != nil {
				t.Fatal(err)
			}
			w.store.file = &failingAlertFile{alertFile: w.store.file, partial: mode == "partial-write", short: mode == "short-write", syncErr: mode == "sync"}
			wantErr := errAlertDisk
			if mode == "short-write" {
				wantErr = io.ErrShortWrite
			}
			if err := w.WriteAlert(&types.Alert{Name: "failed"}); !errors.Is(err, wantErr) {
				t.Fatalf("write error = %v", err)
			}
			if err := w.WriteAlert(&types.Alert{Name: "after-failure"}); !errors.Is(err, wantErr) {
				t.Fatalf("writer did not retain failure: %v", err)
			}
			if peer, err := NewFileAlertWriter(dir); !errors.Is(err, wantErr) {
				if peer != nil {
					_ = peer.Close()
				}
				t.Fatalf("new writer lost failure: %v", err)
			}
			if err := w.Close(); !errors.Is(err, wantErr) {
				t.Fatalf("close lost failure: %v", err)
			}
			if got := readAlertHistory(t, dir); len(got) != 1 || got[0].Name != "committed" {
				t.Fatalf("committed history damaged: %v", got)
			}
			if err := openAlertWriter(t, dir).WriteAlert(&types.Alert{Name: "restarted"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFileAlertWriterOversizedAlert(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	if err := w.WriteAlert(&types.Alert{MatchedRecord: string(make([]byte, maxAlertRecordSize))}); err == nil {
		t.Fatal("accepted oversized alert")
	}
	if err := w.WriteAlert(&types.Alert{Name: "valid"}); err != nil {
		t.Fatal(err)
	}
	if got := readAlertHistory(t, dir); len(got) != 1 || got[0].Name != "valid" {
		t.Fatalf("alerts = %v", got)
	}
}

func BenchmarkFileAlertWriter(b *testing.B) {
	w, err := NewFileAlertWriter(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close()
	alert := &types.Alert{Name: "ssh-novelty", SrcIP: "192.0.2.1", DstIP: "192.0.2.2", MatchedRecord: `{"DstPort":22}`}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := w.WriteAlert(alert); err != nil {
			b.Fatal(err)
		}
	}
}

func TestFileAlertWriterUncleanExit(t *testing.T) {
	if dir := os.Getenv("NETCAP_ALERT_EXIT_TEST"); dir != "" {
		w, err := NewFileAlertWriter(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.WriteAlert(&types.Alert{Name: "before-exit"}); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFileAlertWriterUncleanExit$")
	cmd.Env = append(os.Environ(), "NETCAP_ALERT_EXIT_TEST="+dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child exit: %v\n%s", err, output)
	}
	if got := readAlertHistory(t, dir); len(got) != 1 || got[0].Name != "before-exit" {
		t.Fatalf("lost alert on unclean exit: %v", got)
	}
	if err := openAlertWriter(t, dir).WriteAlert(&types.Alert{Name: "after-exit"}); err != nil {
		t.Fatal(err)
	}
	if got := readAlertHistory(t, dir); len(got) != 2 {
		t.Fatalf("restart alerts = %v", got)
	}
}

func TestEngineFileAlertsVisibleBeforeClose(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	engine, err := NewEngineFromConfig(&Config{Rules: []*Rule{{
		Name: "ssh", Type: "TCP", Expression: "DstPort == 22", Enabled: true,
	}}}, w)
	if err != nil {
		t.Fatal(err)
	}
	count, err := engine.Evaluate(&types.TCP{DstPort: 22, SrcIP: "192.0.2.1", DstIP: "192.0.2.2"})
	if err != nil || count != 1 {
		t.Fatalf("evaluate = %d, %v", count, err)
	}
	if got := readAlertHistory(t, dir); len(got) != 1 || got[0].RuleName != "ssh" {
		t.Fatalf("rule alerts = %v", got)
	}
}
