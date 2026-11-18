package webui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProtoRecompileReportsSnapshotFailure(t *testing.T) {
	protoRuntime.mu.Lock()
	paths, diagnostics, compiled := protoRuntime.searchPaths, protoRuntime.errors, protoRuntime.lastCompiled
	protoRuntime.searchPaths = []string{filepath.Join(t.TempDir(), "missing.proto")}
	protoRuntime.mu.Unlock()
	t.Cleanup(func() {
		protoRuntime.mu.Lock()
		defer protoRuntime.mu.Unlock()
		protoRuntime.searchPaths, protoRuntime.errors, protoRuntime.lastCompiled = paths, diagnostics, compiled
	})
	s := &Server{}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		code int
	}{
		{"missing schema", context.Background(), http.StatusUnprocessableEntity},
		{"canceled request", canceledSchemaRequest(), http.StatusRequestTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleProtoRecompile(w, httptest.NewRequest(http.MethodPost, "/api/proto/recompile", nil).WithContext(tc.ctx))
			if w.Code != tc.code || !strings.Contains(w.Body.String(), `"success":false`) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}

func canceledSchemaRequest() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

type schemaWaitContext struct {
	context.Context
	started chan struct{}
}

func (c schemaWaitContext) Deadline() (time.Time, bool) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Context.Deadline()
}

func TestProtoStatusAvailableWhileRecompileWaits(t *testing.T) {
	for range cap(schemaSnapshotSlots) {
		schemaSnapshotSlots <- struct{}{}
		defer func() { <-schemaSnapshotSlots }()
	}
	protoRuntime.mu.RLock()
	diagnostics, compiled := protoRuntime.errors, protoRuntime.lastCompiled
	protoRuntime.mu.RUnlock()
	defer func() {
		protoRuntime.mu.Lock()
		defer protoRuntime.mu.Unlock()
		protoRuntime.errors, protoRuntime.lastCompiled = diagnostics, compiled
	}()

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		protoRuntime.editMu.Lock()
		defer protoRuntime.editMu.Unlock()
		result <- recompileSchemas(schemaWaitContext{ctx, started}, []string{"fixture.proto"})
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("recompile did not enter snapshot preparation")
	}
	status := make(chan ProtoStatusResponse, 1)
	go func() { status <- (&Server{}).getProtoStatus() }()
	select {
	case <-status:
	case <-time.After(5 * time.Second):
		t.Fatal("status read was blocked by a waiting recompile")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("recompile error = %v, want context.Canceled", err)
	}
}

func TestSchemaSnapshotWaitExpiresWithoutScratch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.proto")
	if err := os.WriteFile(path, []byte(`syntax = "proto3";`), 0600); err != nil {
		t.Fatal(err)
	}
	func() {
		for range cap(schemaSnapshotSlots) {
			schemaSnapshotSlots <- struct{}{}
			defer func() { <-schemaSnapshotSlots }()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		settings := &jobSettings{SchemaPaths: []string{path}}
		got, err := snapshotSchemaSourcesContext(ctx, settings)
		if got != nil {
			got.cleanup()
		}
		if !errors.Is(err, context.DeadlineExceeded) || settings.directory != "" {
			t.Fatalf("wait error=%v scratch=%q", err, settings.directory)
		}
	}()
	snapshot, err := snapshotSchemaSources(&jobSettings{SchemaPaths: []string{path}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.cleanup)
	if len(snapshot.SchemaHashes) != 1 {
		t.Fatal("retry did not snapshot the schema")
	}
}

func TestAnalysisAdmissionCancelsSchemaWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.proto")
	if err := os.WriteFile(path, []byte(`syntax = "proto3";`), 0600); err != nil {
		t.Fatal(err)
	}
	protoRuntime.mu.Lock()
	paths, mappings, alternatives := protoRuntime.searchPaths, protoRuntime.mappings, protoRuntime.alternatives
	protoRuntime.searchPaths = []string{path}
	protoRuntime.mu.Unlock()
	t.Cleanup(func() {
		protoRuntime.mu.Lock()
		defer protoRuntime.mu.Unlock()
		protoRuntime.searchPaths, protoRuntime.mappings, protoRuntime.alternatives = paths, mappings, alternatives
	})
	s := &Server{jobQueue: make(chan *AnalysisJob, 1), shutdownChan: make(chan struct{})}
	defer s.stopProcessingAdmission()
	for range cap(schemaSnapshotSlots) {
		schemaSnapshotSlots <- struct{}{}
		defer func() { <-schemaSnapshotSlots }()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.enqueueAnalysisContext(ctx, &AnalysisJob{}, true) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.RLock()
		owned := s.processingWork > 0
		s.mu.RUnlock()
		if owned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("submission never acquired processing ownership")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("admission error = %v, want cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt saturated snapshot admission")
	}
	s.mu.RLock()
	remaining := s.processingWork
	s.mu.RUnlock()
	if remaining != 0 || len(s.jobQueue) != 0 {
		t.Fatalf("canceled admission retained %d work claims and %d queued jobs", remaining, len(s.jobQueue))
	}
}

func TestSchemaWalkCountsIgnoredAndNestedEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z.proto", "ignored.txt", filepath.Join("nested", "a.proto")} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var visited []string
	visit := func(name string) error { visited = append(visited, name); return nil }
	remaining := 5
	if err := walkSchemaRoot(context.Background(), dir, &remaining, visit); err != nil || remaining != 0 ||
		!slices.Equal(visited, []string{filepath.Join("nested", "a.proto"), "z.proto"}) {
		t.Fatalf("exact budget: visited=%v remaining=%d err=%v", visited, remaining, err)
	}
	visited = nil
	remaining = 4
	if err := walkSchemaRoot(context.Background(), dir, &remaining, visit); err == nil || len(visited) != 0 {
		t.Fatalf("short budget: visited=%v err=%v", visited, err)
	}
}

func TestSchemaSnapshotHonorsRemainingByteBudget(t *testing.T) {
	dir := t.TempDir()
	for i := range 9 {
		name := filepath.Join(dir, fmt.Sprintf("%02d.proto", i))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if i < 8 {
			if err := os.Truncate(name, 2<<20); err != nil {
				t.Fatal(err)
			}
		}
	}
	snapshot, err := snapshotSchemaSources(&jobSettings{SchemaPaths: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.cleanup)
	if len(snapshot.SchemaHashes) != 9 {
		t.Fatal("exact-budget snapshot omitted an empty schema")
	}
	if err := os.Truncate(filepath.Join(dir, "07.proto"), (2<<20)-2); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, "08.proto"), 3); err != nil {
		t.Fatal(err)
	}
	overrun := &jobSettings{SchemaPaths: []string{dir}}
	if _, err := snapshotSchemaSources(overrun); err == nil || !strings.Contains(err.Error(), "exceeds 2 byte limit") {
		t.Fatalf("expected refusal at the remaining two-byte read limit, got %v", err)
	}
	if _, err := os.Stat(overrun.directory); !os.IsNotExist(err) {
		t.Fatalf("failed snapshot left scratch: %v", err)
	}
}

func TestSchemaAdmissionRejectsBroadSourcesBeforeTraversal(t *testing.T) {
	for _, path := range []string{"/etc", "/", "/dev", ".", "/does-not-exist/private-sentinel"} {
		if _, err := admitSchemaSearchPath(path); err == nil || strings.Contains(err.Error(), "private-sentinel") || strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("unexpected admission: %s %v", path, err)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.proto")
	if err := os.WriteFile(path, []byte(`syntax = "proto3"; message Fixture { string value = 1; }`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{dir, path} {
		if _, err := admitSchemaSearchPath(source); err != nil {
			t.Fatal(source, err)
		}
	}
	link := filepath.Join(t.TempDir(), "linked.proto")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := admitSchemaSearchPath(link); err == nil {
		t.Fatal("symlink admitted")
	}
	for i := range 257 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d.proto", i)), []byte(`syntax = "proto3";`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admitSchemaSearchPath(dir); err == nil {
		t.Fatal("schema file bound not enforced")
	}
}
