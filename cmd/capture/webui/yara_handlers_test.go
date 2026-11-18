package webui

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestYaraArtifactWalkBoundsNestedInventory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z.txt", filepath.Join("nested", "b.txt"), filepath.Join("nested", "a.txt")} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var visited []string
	visit := func(name string) error { visited = append(visited, filepath.ToSlash(name)); return nil }
	if err := walkYaraArtifacts(t.Context(), dir, 3, visit); err == nil || !strings.Contains(err.Error(), "traversal limit") || len(visited) != 0 {
		t.Fatalf("over-budget nested directory: visited=%v err=%v", visited, err)
	}
	if err := walkYaraArtifacts(t.Context(), dir, 4, visit); err != nil || !slices.Equal(visited, []string{"nested/a.txt", "nested/b.txt", "z.txt"}) {
		t.Fatalf("exact-budget inventory: visited=%v err=%v", visited, err)
	}
}
