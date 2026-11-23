package auditname

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAliasesResolveToRecordTypes(t *testing.T) {
	for file, want := range map[string]string{"VRRP": "VRRPv2", "GTPv1U": "GTP", "ApplePktap": "PKTAP", "TCP": "TCP", "VRRPv2": "VRRPv2", "Nope": ""} {
		if got := TypeForFile(file); got != want {
			t.Errorf("TypeForFile(%s) = %q, want %q", file, got, want)
		}
	}
	if typ, ok := Alias("gtpv1u"); !ok || typ != "GTP" {
		t.Fatalf("case-insensitive alias: %q %v", typ, ok)
	}
	if got := Candidates("GTP"); !slices.Equal(got, []string{"GTP.ncap.gz", "GTP.ncap", "GTPv1U.ncap.gz", "GTPv1U.ncap"}) {
		t.Fatalf("candidates %v", got)
	}
	if _, typ, ok := Parse("VRRP.csv.gz"); !ok || typ != "VRRPv2" {
		t.Fatalf("parse VRRP.csv.gz: %q %v", typ, ok)
	}
}

func TestResolvePrefersCanonicalAndRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	if _, err := Resolve(dir, "GTP"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	for _, name := range []string{"GTPv1U.ncap.gz", "GTP.ncap"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := Resolve(dir, "GTP"); err != nil || filepath.Base(got) != "GTP.ncap" {
		t.Fatalf("resolved %s %v", got, err)
	}
	if err := os.Symlink(filepath.Join(dir, "GTP.ncap"), filepath.Join(dir, "VRRP.ncap.gz")); err != nil {
		t.Skip(err)
	}
	if _, err := Resolve(dir, "VRRPv2"); err == nil {
		t.Fatal("symlinked audit accepted")
	}
}
