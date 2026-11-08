package resolvers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPopularityInitCachesAndPropagatesFailures(t *testing.T) {
	oldConfig, oldRoot, oldList, oldKey := CurrentConfig, DataBaseFolderPath, popularity.Load(), popularityKey
	t.Cleanup(func() {
		CurrentConfig, DataBaseFolderPath, popularityKey = oldConfig, oldRoot, oldKey
		popularity.Store(oldList)
	})
	DataBaseFolderPath = t.TempDir()
	CurrentConfig = Config{}
	path := filepath.Join(DataBaseFolderPath, ManagedPopularityFile)
	if err := os.WriteFile(path, []byte("NetAPI_Rank,Domain\n1,example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitDNSWhitelist(); err != nil || !IsPopularHTTPHost("www.example.com:443") {
		t.Fatal("managed default", err)
	}
	first := popularity.Load()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := InitDNSWhitelist(); err != nil || popularity.Load() != first {
		t.Fatal("second initialization reloaded validated data", err)
	}
	CurrentConfig.DomainPopularityList = filepath.Join(t.TempDir(), "missing.csv")
	if err := InitDNSWhitelist(); err == nil || IsPopularHTTPHost("example.com") {
		t.Fatal("failed initialization retained data or hid failure", err)
	}
	if err := InitDNSWhitelist(); err == nil {
		t.Fatal("retry hid failure")
	}
	CurrentConfig.DisableDomainPopularity = true
	if err := InitDNSWhitelist(); err != nil || IsPopularHTTPHost("example.com") {
		t.Fatal("opt-out", err)
	}
}

func TestManagedPopularitySkipsUnregistrableEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ManagedPopularityFile)
	data := "NetAPI_Rank,Domain\n1,googleapis.com\n2,alice.github.io\n3,ac.yu\n4,www.example.com\n5,aquila.it\n6,example.com\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	list, stats, err := LoadManagedDomainPopularityList(dir)
	if err != nil || stats.Loaded != 2 || stats.Skipped != 4 || stats.Invalid != 0 {
		t.Fatal(stats, err)
	}
	if list.ContainsDNS("tenant.googleapis.com") || list.ContainsDNS("bob.github.io") || !list.ContainsDNS("alice.github.io") {
		t.Fatal("shared suffix leaked membership across tenants")
	}
	if _, _, err := LoadDomainPopularityList(path, "netapi", t.TempDir()); err == nil {
		t.Fatal("external override lost strict validation")
	}
	if err := os.WriteFile(path, []byte("NetAPI_Rank,Domain\n1,bad/domain.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadManagedDomainPopularityList(dir); err == nil {
		t.Fatal("malformed input accepted")
	}
}
