//go:build !noyara

package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestYaraNativeCompileScanAndErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qualification.yar")
	source := `rule qualification { strings: $a = "netcap-yara-qualification" condition: $a }`
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	scanner, err := NewYaraScanner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if scanner.rules != nil {
			scanner.rules.Destroy()
		}
	}()
	if !YaraAvailable() || scanner.RuleCount() != 1 {
		t.Fatal("native scanner did not load the rule")
	}
	for _, tc := range []struct {
		data string
		want []string
	}{
		{"netcap-yara-qualification", []string{"qualification"}},
		{"unrelated payload", nil},
	} {
		got, err := scanner.ScanBytes([]byte(tc.data))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("scan %q: got %v, %v; want %v", tc.data, got, err, tc.want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.ScanBytesContext(ctx, []byte("netcap-yara-qualification")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan: %v", err)
	}
	if err := ValidateYaraSource(`rule broken { condition: }`); err == nil {
		t.Fatal("invalid source accepted")
	}
	if err := ValidateYaraSource(`include "other.yar"`); err == nil {
		t.Fatal("include accepted despite EnableIncludes(false)")
	}
	if _, err := scanner.ScanFile(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
	digest := scanner.Digest()
	if err := os.WriteFile(path, []byte(`rule broken { condition: }`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := scanner.Reload(); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if scanner.Digest() != digest || scanner.RuleCount() != 1 {
		t.Fatal("failed reload replaced working rules")
	}
	if got, err := scanner.ScanBytes([]byte("netcap-yara-qualification")); err != nil || len(got) != 1 {
		t.Fatalf("scan after failed reload: %v, %v", got, err)
	}
}
