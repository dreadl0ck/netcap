package resolvers

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enrichment"
)

func TestInstalledDeviceCataloguesDefaultAndRetainedStatus(t *testing.T) {
	oldRoot, oldDBs, oldMAC, oldDHCP := ConfigRootPath, DataBaseFolderPath, macCatalogue.Load(), dhcpCatalogue.Load()
	deviceStatus.Lock()
	oldMACStatus, oldDHCPStatus := deviceStatus.MAC, deviceStatus.DHCP
	deviceStatus.Unlock()
	t.Cleanup(func() {
		ConfigRootPath = oldRoot
		DataBaseFolderPath = oldDBs
		macCatalogue.Store(oldMAC)
		dhcpCatalogue.Store(oldDHCP)
		deviceStatus.Lock()
		deviceStatus.MAC, deviceStatus.DHCP = oldMACStatus, oldDHCPStatus
		deviceStatus.Unlock()
	})
	ConfigRootPath = t.TempDir()
	DataBaseFolderPath = filepath.Join(ConfigRootPath, "dbs")
	t.Setenv("NC_ENRICHMENT_ROOT", filepath.Join(ConfigRootPath, "enrichment"))
	t.Setenv("NC_MAC_CATALOGUE", "")
	t.Setenv("NC_DHCP_CATALOGUE", "")
	macCatalogue.Store(nil)
	dhcpCatalogue.Store(nil)
	deviceStatus.Lock()
	deviceStatus.MAC, deviceStatus.DHCP = DeviceCatalogueStatus{}, DeviceCatalogueStatus{}
	deviceStatus.Unlock()
	// Test-only keys sign the real candidate; no production credential is used.
	root := ed25519.NewKeyFromSeed(make([]byte, 32))
	seed := make([]byte, 32)
	seed[0] = 1
	signer := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(1794000000, 0)
	archive, p, err := enrichment.Pack("../devicecatalog/channel")
	if err != nil {
		t.Fatal(err)
	}
	p.Sequence = 1
	p.IssuedAt = now.Unix()
	p.ExpiresAt = now.Add(time.Hour).Unix()
	k := enrichment.Key{Format: "netcap-enrichment-signing-key/v1", PublicKey: signer.Public().(ed25519.PublicKey), Epoch: 1, NotBefore: now.Add(-time.Minute).Unix(), NotAfter: now.Add(24 * time.Hour).Unix(), Channel: enrichment.Channel, Capabilities: []string{enrichment.Capability}, MinimumFormat: 1}
	kb, _ := json.Marshal(k)
	pb, _ := json.Marshal(p)
	envelope := enrichment.Envelope{Certificate: enrichment.SignedBytes{Payload: kb, Signature: ed25519.Sign(root, kb)}, SignedBytes: enrichment.SignedBytes{Payload: pb, Signature: ed25519.Sign(signer, pb)}}
	trust := root.Public().(ed25519.PublicKey)
	if err = enrichment.Install(enrichment.Root(ConfigRootPath), envelope, archive, trust, now); err != nil {
		t.Fatal(err)
	}
	for _, status := range installedDeviceCatalogueStatuses(enrichment.Root(ConfigRootPath), trust, now) {
		if status.State != "verified-installed" || status.Scope != "installation" || status.Version == "" {
			t.Fatalf("installed inventory: %+v", status)
		}
	}
	if macCatalogue.Load() != nil || dhcpCatalogue.Load() != nil || DeviceCatalogueStatuses()[0].State != "not-initialized" {
		t.Fatal("installation inspection mutated capture state")
	}
	initDeviceCataloguesWithTrust(true, true, trust, now)
	if LookupDHCPFingerprintLocal("1,3,6") != "Xbox 360" || macCatalogue.Load() == nil {
		t.Fatal("default installed catalogues not loaded")
	}
	for _, status := range DeviceCatalogueStatuses() {
		if status.State != "verified-installed" || status.Attribution == "" || status.DownloadFile == "" {
			t.Fatalf("%+v", status)
		}
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				_ = LookupDHCPFingerprintLocal("1,3,6")
				_ = LookupManufacturer("00:00:0c:00:00:01")
				_ = DeviceCatalogueStatuses()
			}
		})
	}
	initDeviceCataloguesWithTrust(true, true, trust, now)
	workers.Wait()
	// An unrelated core update cannot replace or clear managed enrichment.
	if err = os.MkdirAll(filepath.Join(ConfigRootPath, "dbs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(ConfigRootPath, "dbs", "dhcp-fingerprints.json"), []byte(`{"1,3,6":{"device_name":"stale"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	initDeviceCataloguesWithTrust(true, true, trust, now)
	if LookupDHCPFingerprintLocal("1,3,6") != "Xbox 360" {
		t.Fatal("core update changed optional source")
	}
	dir, err := enrichment.Resolve(enrichment.Root(ConfigRootPath), trust, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "mac-organizations.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	initDeviceCataloguesWithTrust(true, true, trust, now)
	for _, status := range DeviceCatalogueStatuses() {
		if status.State != "retained-after-error" || status.Version == "" || status.Attribution == "" {
			t.Fatalf("%+v", status)
		}
	}
	if LookupDHCPFingerprintLocal("1,3,6") != "Xbox 360" {
		t.Fatal("failed admission erased old catalogue")
	}
	t.Setenv("NC_DHCP_CATALOGUE", "../devicecatalog/data/dhcp-catalogue-v1.json")
	initDeviceCataloguesWithTrust(false, true, trust, now)
	if DeviceCatalogueStatuses()[0].State != "explicit-trusted-override" {
		t.Fatal("trusted external override did not take precedence")
	}
	coreFile := filepath.Join(DataBaseFolderPath, "dhcp-fingerprints-odbl.json")
	data, err := os.ReadFile("../devicecatalog/data/dhcp-catalogue-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(coreFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NC_DHCP_CATALOGUE", coreFile)
	initDeviceCataloguesWithTrust(false, true, trust, now)
	status := DeviceCatalogueStatuses()[0]
	if status.State != "retained-after-error" || status.Reason != "explicit device catalogue must be outside core database directory" {
		t.Fatalf("%+v", status)
	}
}
