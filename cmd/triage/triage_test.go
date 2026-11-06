package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/dreadl0ck/netcap/internal/identity"
	"os"
	"path/filepath"
	"testing"
)

func TestTriageRetainsQualifiedIdentityReport(t *testing.T) {
	dir := t.TempDir()
	r := identity.Report{Schema: 1, Hosts: []identity.Host{{Scope: "vlan1", IP: "10.0.0.2", HostnameState: "conflicting-observations"}}}
	b, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(dir, identity.Filename), b, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	c := GetCommand()
	c.Writer = &output
	if err := c.Run(context.Background(), []string{"triage", "--read", dir, "--json"}); err != nil {
		t.Fatal(err)
	}
	var got identity.Report
	if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.Hosts[0].HostnameState != "conflicting-observations" {
		t.Fatal(err)
	}
}
