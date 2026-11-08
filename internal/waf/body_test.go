package waf

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/policy"
)

type repeatedBody struct{ remaining int64 }

func spool(r io.Reader, max, length int64) (*bodyStore, error) {
	b, _ := firewalltransport.NewBufferBudget(128 << 20)
	return spoolBudget(r, max, length, b)
}
func spoolBody(r io.Reader, h http.Header, max, length int64) (*bodyStore, error) {
	b, _ := firewalltransport.NewBufferBudget(128 << 20)
	return spoolBodyBudget(r, h, max, length, b)
}

func (r *repeatedBody) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := range p[:n] {
		p[i] = 'x'
	}
	r.remaining -= n
	return int(n), nil
}

func TestSpool64MiBSharedViewsAndCleanup(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	b, err := spool(&repeatedBody{remaining: MaxInspectionBodyBytes}, MaxInspectionBodyBytes, -1)
	if err != nil {
		t.Fatal(err)
	}
	if b.file == nil || len(b.data) != 0 || b.size != MaxInspectionBodyBytes {
		t.Fatalf("large body buffered in RAM: size=%d memory=%d", b.size, len(b.data))
	}
	path := b.file.Name()
	stat, err := b.file.Stat()
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("spool permission: %v %v", stat, err)
	}
	views := []io.ReadCloser{b.view(), b.view(), b.view()}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var hashes [3][]byte
	for i, v := range views {
		wg.Add(1)
		go func(i int, v io.ReadCloser) {
			defer wg.Done()
			defer v.Close()
			h := sha256.New()
			n, err := io.Copy(h, v)
			if err != nil || n != MaxInspectionBodyBytes {
				t.Errorf("shared view: %d %v", n, err)
			}
			hashes[i] = h.Sum(nil)
		}(i, v)
	}
	wg.Wait()
	if !bytes.Equal(hashes[0], hashes[1]) || !bytes.Equal(hashes[1], hashes[2]) {
		t.Fatal("views interfered")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool leaked: %v", err)
	}
}

func TestSpoolFailureRemovesPartialFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	for _, length := range []int64{-1, 100 << 10, 64 << 10} {
		_, err := spool(&repeatedBody{remaining: 90 << 10}, 80<<10, length)
		if err == nil {
			t.Fatal("over-limit spool accepted")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("partial spool leak: %v %v", entries, err)
		}
	}
}

func TestSpoolGzipWireAndExpandedBounds(t *testing.T) {
	var wire bytes.Buffer
	z := gzip.NewWriter(&wire)
	_, _ = io.WriteString(z, strings.Repeat("x", 2<<20))
	_ = z.Close()
	h := http.Header{"Content-Encoding": []string{"gzip"}}
	b, err := spoolBody(bytes.NewReader(wire.Bytes()), h, 3<<20, int64(wire.Len()))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.size != 2<<20 || b.file == nil {
		t.Fatalf("expanded size=%d disk=%v", b.size, b.file != nil)
	}
	if _, err := spoolBody(bytes.NewReader(wire.Bytes()), h, 1<<20, int64(wire.Len())); err == nil {
		t.Fatal("gzip expansion bypassed limit")
	}
}

func TestNativeBodyNeverTruncates(t *testing.T) {
	b, err := spool(strings.NewReader(strings.Repeat("a", NativeBodyBytes+1)), MaxInspectionBodyBytes, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p := compiled(t, "enforce", "request", `Body contains "late"`)
	if _, err := nativeBody(p, "request", b); err == nil {
		t.Fatal("oversized body-dependent policy evaluated a projection")
	}
}

type stalledBody struct{}

func (stalledBody) Read([]byte) (int, error) { return 0, nil }

func TestSpoolRejectsNoProgress(t *testing.T) {
	if _, err := spool(stalledBody{}, 64, -1); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("no-progress reader: %v", err)
	}
}

func TestBodyCapabilitiesExposeEffectiveNativeLimit(t *testing.T) {
	c := config("http://127.0.0.1:1")
	c.MaxBodyBytes = MaxInspectionBodyBytes
	c.MaxResponseBytes = MaxInspectionBodyBytes
	f := firewall(t, c, compiled(t, "enforce", "request", `Body contains "secret"`))
	cap := f.BodyCapabilities()
	if cap.MaxRequestBytes != 64<<20 || cap.EffectiveRequestBytes != NativeBodyBytes || !cap.RequestRequiresBody || cap.MemorySpoolBytes != 64<<10 || cap.MaxBufferedBytes != 64<<20 || cap.BufferedBytes != 0 {
		t.Fatalf("misleading advertised body capability: %+v", cap)
	}
}

func TestSpoolAggregateBudgetAndSharedViewLifetime(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	budget, _ := firewalltransport.NewBufferBudget(192 << 10)
	b, err := spoolBudget(&repeatedBody{remaining: 128 << 10}, MaxInspectionBodyBytes, -1, budget)
	if err != nil {
		t.Fatal(err)
	}
	view := b.view()
	path := b.file.Name()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Used() != 128<<10 {
		t.Fatalf("owner close released a live view: %d", budget.Used())
	}
	if _, err := spoolBudget(&repeatedBody{remaining: 128 << 10}, MaxInspectionBodyBytes, -1, budget); err == nil {
		t.Fatal("concurrent spool exceeded aggregate budget")
	}
	if budget.Used() != 128<<10 {
		t.Fatalf("failed spool leaked quota: %d", budget.Used())
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Used() != 0 {
		t.Fatalf("view close leaked quota: %d", budget.Used())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("view spool leaked: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("rejected spool leaked files: %v", entries)
	}
}

func TestSpoolGzipSharesBudgetWithWireRepresentation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	var wire bytes.Buffer
	z := gzip.NewWriter(&wire)
	_, _ = io.Copy(z, &repeatedBody{remaining: 256 << 10})
	_ = z.Close()
	budget, _ := firewalltransport.NewBufferBudget(128 << 10)
	_, err := spoolBodyBudget(bytes.NewReader(wire.Bytes()), http.Header{"Content-Encoding": []string{"gzip"}}, 1<<20, int64(wire.Len()), budget)
	var reject rejection
	if !errors.As(err, &reject) || reject.status != 503 || budget.Used() != 0 {
		t.Fatalf("expansion quota: err=%v used=%d", err, budget.Used())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("expansion leaked files: %v", entries)
	}
}

func TestBodyIndependent64MiBProxySkipsNativeBodyCopy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != 64<<20 {
			t.Errorf("large forward: %d %v", n, err)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	c := config(origin.URL)
	c.MaxBodyBytes = 64 << 20
	c.MaxBufferedBytes = 128 << 20
	c.BodyTimeout = "30s"
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	if err := f.SetEvaluator(func(_ context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
		if e.Body != "" {
			t.Errorf("body-independent event copied %d bytes", len(e.Body))
		}
		return p.Evaluate(e)
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://route.example/upload", &repeatedBody{remaining: 64 << 20})
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 || f.buffers.Used() != 0 {
		t.Fatalf("large body-independent request: status=%d used=%d", w.Code, f.buffers.Used())
	}
}

func TestRuntimeQuotaRejectsConcurrentSpoolsWithoutDiskGrowth(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	ready := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(ready)
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	defer func() { once.Do(func() { close(release) }); origin.Close() }()
	c := config(origin.URL)
	c.MaxBodyBytes = 256 << 10
	c.MaxBufferedBytes = 400 << 10
	f := firewall(t, c, compiled(t, "enforce", "request", ""))
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.ServeHTTP(first, httptest.NewRequest("POST", "http://route.example/", &repeatedBody{remaining: 192 << 10}))
	}()
	<-ready
	second := httptest.NewRecorder()
	f.ServeHTTP(second, httptest.NewRequest("POST", "http://route.example/", &repeatedBody{remaining: 256 << 10}))
	if second.Code != 503 || f.buffers.Used() != 192<<10 {
		t.Fatalf("concurrent quota: status=%d used=%d", second.Code, f.buffers.Used())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("rejected partial spool survived: %v %v", entries, err)
	}
	once.Do(func() { close(release) })
	<-done
	if first.Code != 200 || f.buffers.Used() != 0 {
		t.Fatalf("retained request budget: status=%d used=%d", first.Code, f.buffers.Used())
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("completed runtime leaked files: %v", entries)
	}
}

func TestMemorySpoolCapacityAndCopyPeakAreCharged(t *testing.T) {
	for _, limit := range []int64{4096, 8192} {
		budget, _ := firewalltransport.NewBufferBudget(limit)
		input := io.MultiReader(strings.NewReader(strings.Repeat("x", 1000)), strings.NewReader(strings.Repeat("y", 100)))
		body, err := spoolBudget(input, 64<<10, 1100, budget)
		if limit == 4096 {
			var reject rejection
			if !errors.As(err, &reject) || reject.status != 503 || budget.Used() != 0 {
				t.Fatalf("spool growth bypassed simultaneous-copy quota: error=%v used=%d", err, budget.Used())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(body.data) != 1100 || cap(body.data) != 2000 || budget.Used() != int64(cap(body.data)) {
			t.Fatalf("memory spool capacity undercharged: len=%d cap=%d used=%d", len(body.data), cap(body.data), budget.Used())
		}
		if string(body.data) != strings.Repeat("x", 1000)+strings.Repeat("y", 100) {
			t.Fatal("spool copy changed data")
		}
		_ = body.Close()
		if budget.Used() != 0 {
			t.Fatalf("memory spool quota leaked: %d", budget.Used())
		}
	}
}

func TestSpoolSpillChargesMemoryAndDiskDuringCopy(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	for _, limit := range []int64{191 << 10, 192 << 10} {
		budget, _ := firewalltransport.NewBufferBudget(limit)
		body, err := spoolBudget(&repeatedBody{remaining: 96 << 10}, 128<<10, -1, budget)
		if limit == 191<<10 {
			var reject rejection
			if !errors.As(err, &reject) || reject.status != 503 {
				t.Fatalf("spill did not reserve overlapping storage: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if body.file == nil || body.data != nil || budget.Used() != 96<<10 {
				t.Fatalf("spill retained wrong storage quota: file=%v memory=%d used=%d", body.file != nil, len(body.data), budget.Used())
			}
			_ = body.Close()
		}
		entries, _ := os.ReadDir(dir)
		if budget.Used() != 0 || len(entries) != 0 {
			t.Fatalf("spill quota/files leaked: used=%d files=%v", budget.Used(), entries)
		}
	}
}
