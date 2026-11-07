package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/urfave/cli/v3"
)

func TestFleetOperationsCLIContracts(t *testing.T) {
	token := strings.Repeat("s", 32)
	t.Setenv("OPERATIONS_TEST_TOKEN", token)
	scope := firewallfleet.Scope{Tenant: "tenant", App: "app"}
	s, err := firewallfleet.New(firewallfleet.Config{StateDir: filepath.Join(t.TempDir(), "state"), Token: token})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	v, err := s.Execute(context.Background(), token, "stage", firewallfleet.Request{Scope: scope, Bundle: `{"version":"1","id":"cli","mode":"enforce","default":"allow"}`})
	if err != nil {
		t.Fatal(err)
	}
	rev := v.(map[string]string)["revision"]
	var stdout, stderr bytes.Buffer
	run := func(op string, input any) error {
		stdout.Reset()
		stderr.Reset()
		file := followJSON(t, filepath.Join(t.TempDir(), "input.json"), input)
		command := &cli.Command{Name: "net", Writer: &stdout, ErrWriter: &stderr, Commands: []*cli.Command{GetCommand()}}
		return command.Run(context.Background(), []string{"net", "firewall", "fleet-operations", "--url", server.URL, "--token-env", "OPERATIONS_TEST_TOKEN", "--operation", op, "--input", file})
	}
	r := map[string]any{"scope": scope, "revisions": []string{rev}}
	if err = run("retention_preview", r); err != nil {
		t.Fatal(err)
	}
	var plan firewallfleet.RetentionReport
	if err = json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	r["expected_plan"] = plan.Plan
	if err = run("prune", r); err != nil {
		t.Fatal(err)
	}
	if err = run("audit_export", map[string]any{"scope": scope, "limit": 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), `"more":"true"`) || !strings.Contains(stdout.String(), `"outcome":"committed"`) {
		t.Fatal("export page/cursor contract", stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), token) {
		t.Fatal("token exported")
	}
}
