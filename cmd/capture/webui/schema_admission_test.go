package webui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

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
