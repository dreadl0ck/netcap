package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/servicesignatures"
	"github.com/dreadl0ck/netcap/types"
)

func TestServiceSignaturesStaleInstallAndWarning(t *testing.T) {
	oldPath, oldWriter, oldEngine := resolvers.DataBaseFolderPath, signatureWarningWriter, signatureEngine.Load()
	oldInventory := signatureInventory.Load()
	dir := t.TempDir()
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
