package servicesignatures

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryRecordsActualFallbackAndHash(t *testing.T) {
	e, err := Load(filepath.Join(t.TempDir(), FileName))
	i := e.Inventory("capture", err)
	if i.State != "loaded" || i.Source != "builtin" || !i.Degraded || i.Warning == "" || i.RuleCount != 4 || i.SourceSHA256 != fmt.Sprintf("%x", sha256.Sum256(builtin)) {
		t.Fatalf("%+v", i)
	}
	dir := t.TempDir()
	if err := WriteInventory(dir, i); err != nil {
		t.Fatal(err)
	}
	got, err := ReadInventory(filepath.Join(dir, InventoryFileName))
	if err != nil || got.SourceSHA256 != i.SourceSHA256 || got.Warning != i.Warning || !got.CheckedAt.Equal(i.CheckedAt) {
		t.Fatalf("%+v %v", got, err)
	}
	if err := WriteInventory(dir, UnavailableInventory("disabled", "Service decoder disabled")); err != nil {
		t.Fatal(err)
	}
	got, err = ReadInventory(filepath.Join(dir, InventoryFileName))
	if err != nil || got.State != "disabled" || got.Source != "none" || got.RuleCount != 0 || got.Catalogue != nil {
		t.Fatalf("stale state: %+v %v", got, err)
	}
}

func TestV1RejectsEnabledField(t *testing.T) {
	for _, value := range []string{"true", "false", "null", "1"} {
		b := bytes.Replace(builtin, []byte(`"id":"netcap.ssh.ident.v1"`), []byte(`"id":"netcap.ssh.ident.v1","enabled":`+value), 1)
		if _, err := Parse(bytes.NewReader(b)); err == nil {
			t.Fatalf("v1 accepted enabled:%s", value)
		}
	}
	if _, err := Parse(bytes.NewReader(bytes.Replace(builtin, []byte(`"protocol"`), []byte(`"Protocol"`), 1))); err == nil {
		t.Fatal("accepted noncanonical key casing")
	}
}

func TestInvalidInventoryRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), InventoryFileName)
	for _, data := range [][]byte{[]byte(`{}`), []byte(`{"format":"netcap-service-signature-inventory","schema_version":2}`), bytes.Repeat([]byte{' '}, 2*MaxCatalogueBytes+1)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadInventory(path); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
	}
}
