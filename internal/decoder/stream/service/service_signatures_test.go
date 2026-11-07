package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/enrichment"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/internal/webtech/testfixture"
	"github.com/dreadl0ck/netcap/types"
)

func TestServiceSignaturesStaleInstallAndWarning(t *testing.T) {
	oldPath, oldWriter, oldEngine := resolvers.DataBaseFolderPath, signatureWarningWriter, signatureEngine.Load()
	oldInventory := signatureInventory.Load()
	dir := t.TempDir()
	t.Setenv("NC_ENRICHMENT_ROOT", t.TempDir())
	resolvers.DataBaseFolderPath = dir
	var warnings bytes.Buffer
	signatureWarningWriter = &warnings
	t.Cleanup(func() {
		resolvers.DataBaseFolderPath = oldPath
		signatureWarningWriter = oldWriter
		signatureEngine.Store(oldEngine)
		signatureInventory.Store(oldInventory)
	})
	// A retired file is never interpreted, even when present on an upgrade.
	core := bytes.Replace(servicesignatures.PublicationBytes(), []byte("netcap.ssh.ident.v1"), []byte("netcap.core.must-not-load.v1"), 1)
	if err := os.WriteFile(filepath.Join(dir, servicesignatures.FileName), core, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nmap-service-probes")
	legacy := []byte("uninterpreted legacy bytes")
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []bool{false, true} {
		if invalid {
			if err := os.WriteFile(filepath.Join(dir, servicesignatures.FileName), []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		warnings.Reset()
		if err := initServiceProbes(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(warnings.String(), "degraded") {
			t.Fatal("missing stderr warning")
		}
		s := &service{Service: &types.Service{Protocol: "TCP", Port: 9999}}
		MatchServiceProbes(s, []byte("220 host.example ESMTP ready\r\n"), "fixture")
		if s.Name != "smtp" || s.MatchedProbeID != "netcap.smtp.greeting.v1" {
			t.Fatalf("%+v", s.Service)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, legacy) {
		t.Fatal("legacy file was changed")
	}
}

func TestVerifiedOptionalServiceSnapshotIsImmutable(t *testing.T) {
	f, err := testfixture.Build()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "enrichment")
	if err = f.Install(root); err != nil {
		t.Fatal(err)
	}
	e, err := loadOptionalSignatures(root, f.Trust, time.Unix(f.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	inventory := e.Inventory("capture", err)
	if inventory.Degraded || inventory.Source != "external" || inventory.RuleCount != 4 {
		t.Fatal(inventory)
	}
	dir, err := enrichment.Resolve(root, f.Trust, time.Unix(f.Now, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	r, ok := e.Identify([]byte("SSH-2.0-Fixture_1.0\r\n"), "tcp", "server-to-client")
	if !ok || r.ID != "netcap.ssh.ident.v1" {
		t.Fatal("snapshot reread disk", r)
	}
	_, err = loadOptionalSignatures(root, f.Trust, time.Unix(f.Now, 0))
	if err == nil {
		t.Fatal("removed verified snapshot accepted")
	}
}

func TestHTTPHeaderCannotMatchBodyOrOverrideRuleID(t *testing.T) {
	s := &service{Service: &types.Service{Protocol: "TCP"}}
	MatchServiceProbes(s, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nServer: injected/1\r\n"), "fixture")
	if s.Product != "" || s.MatchedProbeID != "netcap.http.response.v1" {
		t.Fatalf("body treated as headers: %+v", s.Service)
	}
	s = &service{Service: &types.Service{MatchedProbeID: "netcap.custom.http.v1"}}
	parseHeaderValue(s, "Server", "Fixture/1", "fixture")
	if s.MatchedProbeID != "netcap.custom.http.v1" {
		t.Fatal("rule ID overwritten")
	}
}
