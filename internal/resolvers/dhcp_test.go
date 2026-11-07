package resolvers

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type forbiddenTransport struct{ t *testing.T }

func (f forbiddenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Error("DHCP attempted network access")
	return nil, errors.New("forbidden")
}

func TestDHCPLegacyFilesInert(t *testing.T) {
	oldCatalogue := dhcpCatalogue.Load()
	dhcpCatalogue.Store(nil)
	t.Cleanup(func() { dhcpCatalogue.Store(oldCatalogue) })
	t.Setenv("NC_DHCP_CATALOGUE", "")
	dir := t.TempDir()
	old, oldClient := DataBaseFolderPath, http.DefaultClient
	DataBaseFolderPath = dir
	http.DefaultClient = &http.Client{Transport: forbiddenTransport{t}}
	t.Cleanup(func() { DataBaseFolderPath = old; http.DefaultClient = oldClient })
	t.Setenv("FINGERBANK_API_KEY", "must-not-be-used")
	path := filepath.Join(dir, "dhcp-fingerprints.json")
	data := []byte(`{"1,3,6":{"device_name":"must-not-load"}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	InitDHCPFingerprintAPIKey()
	InitDHCPFingerprintDB()
	if got := LookupDHCPFingerprintLocal("1,3,6"); got != "" {
		t.Fatal(got)
	}
	if got, err := LookupDHCPFingerprint("1,3,6", "test", nil); got != nil || !errors.Is(err, ErrDHCPEnrichmentDisabled) {
		t.Fatalf("%v %v", got, err)
	}
	SaveFingerprintDB()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(data) {
		t.Fatalf("legacy file modified: %q %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected cache writes: %v %v", entries, err)
	}
}

func TestDHCPExplicitCatalogue(t *testing.T) {
	old := dhcpCatalogue.Load()
	t.Cleanup(func() { dhcpCatalogue.Store(old) })
	if err := LoadDHCPCatalogue("../devicecatalog/data/dhcp-catalogue-v1.json"); err != nil {
		t.Fatal(err)
	}
	if LookupDHCPFingerprintLocal("1,3,6") != "Xbox 360" {
		t.Fatal("missing source-derived rule")
	}
	if err := LoadDHCPCatalogue("missing"); err == nil {
		t.Fatal("accepted missing")
	}
	if LookupDHCPFingerprintLocal("1,3,6") != "Xbox 360" {
		t.Fatal("failed refresh erased rule")
	}
}

func TestMACSupplementInert(t *testing.T) {
	old := DataBaseFolderPath
	DataBaseFolderPath = t.TempDir()
	t.Cleanup(func() { DataBaseFolderPath = old })
	before := LookupManufacturer("00:00:0c:00:00:01")
	if before == "" {
		t.Fatal("missing built-in MAC fallback")
	}
	if err := os.WriteFile(filepath.Join(DataBaseFolderPath, "macaddress.io-db.json"), []byte(`{"oui":"00:00:0C","companyName":"must-not-load"}`), 0600); err != nil {
		t.Fatal(err)
	}
	initMACResolver()
	if got := LookupManufacturer("00:00:0c:00:00:01"); got != before {
		t.Fatalf("%q != builtin %q", got, before)
	}
}
