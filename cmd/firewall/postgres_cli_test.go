package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

func TestPostgresBootstrapEnvironmentResolution(t *testing.T) {
	const raw = "postgres://operator:configuration-secret@127.0.0.1:1/firewall?sslmode=disable"
	t.Setenv("FOLLOW_DATABASE_URL", raw)
	t.Setenv("FOLLOW_OPERATOR", strings.Repeat("a", 32))
	scope := firewallstate.Scope{Tenant: "tenant", App: "ha"}
	fleetFile := followJSON(t, filepath.Join(t.TempDir(), "fleet.json"), serviceFile{DatabaseURLEnv: "FOLLOW_DATABASE_URL", DatabaseNamespace: "cli_fleet", TokenEnv: "FOLLOW_OPERATOR", AllowEffects: true, RollbackOnFailure: true, Targets: []principalFile{{ID: "target", TokenEnv: "FOLLOW_OPERATOR", Scope: scope}}})
	first, err := fleetConfig(fleetFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fleetConfig(fleetFile)
	if err != nil {
		t.Fatal(err)
	}
	if first.DatabaseURL != raw || first.DatabaseNamespace != "cli_fleet" || first.StateDir != "" || !first.AllowEffects || !first.RollbackOnFailure || !reflect.DeepEqual(first, second) {
		t.Fatal("fleet replica bootstrap resolution differs")
	}
	stateFile := followJSON(t, filepath.Join(t.TempDir(), "state.json"), serviceFile{DatabaseURLEnv: "FOLLOW_DATABASE_URL", DatabaseNamespace: "cli_state", MaxKeys: 100, Principals: []principalFile{{ID: "proxy", TokenEnv: "FOLLOW_OPERATOR", Scope: scope}}})
	state, err := stateConfig(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if state.DatabaseURL != raw || state.DatabaseNamespace != "cli_state" || state.StateDir != "" || state.MaxKeys != 100 || len(state.Principals) != 1 {
		t.Fatal("sharedstate PostgreSQL bootstrap lost fields")
	}
}

func TestPostgresBootstrapRejectsRawSecretsAndConflicts(t *testing.T) {
	const raw = "postgres://operator:bootstrap-secret@127.0.0.1:1/firewall?sslmode=disable"
	t.Setenv("FOLLOW_DATABASE_URL", raw)
	for _, input := range []any{
		map[string]any{"databaseURL": raw},
		map[string]any{"databaseURLEnv": "FOLLOW_DATABASE_URL", "databaseNamespace": "a", "stateDir": t.TempDir()},
		map[string]any{"databaseNamespace": "orphan"},
		map[string]any{"databaseURLEnv": raw},
		map[string]any{"databaseURLEnv": "FOLLOW_DATABASE_UNSET"},
		map[string]any{"databaseURLEnv": "FOLLOW_DATABASE_URL", "token": "bootstrap-secret"},
		map[string]any{"databaseURLEnv": "FOLLOW_DATABASE_URL", "principals": []any{map[string]any{"id": "proxy", "token": "bootstrap-secret"}}},
	} {
		file := followJSON(t, filepath.Join(t.TempDir(), "bad.json"), input)
		for _, load := range []func(string) error{func(path string) error { _, err := fleetConfig(path); return err }, func(path string) error { _, err := stateConfig(path); return err }} {
			err := load(file)
			if err == nil {
				t.Fatal("invalid PostgreSQL bootstrap accepted")
			}
			if strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "bootstrap-secret") {
				t.Fatal("database secret leaked in validation error")
			}
		}
	}
}

func TestPostgresCommandsRedactFailuresAndRequireNativeBackup(t *testing.T) {
	const raw = "postgres://operator:command-secret@127.0.0.1:1/firewall?sslmode=disable"
	t.Setenv("FOLLOW_DATABASE_URL", raw)
	t.Setenv("FOLLOW_OPERATOR", strings.Repeat("a", 32))
	for _, service := range []string{"fleet", "sharedstate"} {
		t.Run(service, func(t *testing.T) {
			dir := t.TempDir()
			bootstrap := serviceFile{DatabaseURLEnv: "FOLLOW_DATABASE_URL", DatabaseNamespace: "cli_failure"}
			command := "fleet-controller"
			if service == "fleet" {
				bootstrap.TokenEnv = "FOLLOW_OPERATOR"
			} else {
				command = "sharedstate"
				bootstrap.Principals = []principalFile{{ID: "proxy", TokenEnv: "FOLLOW_OPERATOR", Scope: firewallstate.Scope{Tenant: "tenant", App: "ha"}}}
			}
			file := followJSON(t, filepath.Join(dir, "service.json"), bootstrap)
			p := followStart(t, command, "--config", file, "--listen", followAddr(t))
			select {
			case <-p.done:
			case <-time.After(10 * time.Second):
				t.Fatal("PostgreSQL failure did not respect startup deadline")
			}
			if p.err == nil || !strings.Contains(p.log.String(), "PostgreSQL") {
				t.Fatal("missing PostgreSQL startup failure")
			}
			if strings.Contains(p.log.String(), raw) || strings.Contains(p.log.String(), "command-secret") {
				t.Fatal("database secret logged")
			}
			output := filepath.Join(dir, "snapshot.sqlite")
			backup := followStart(t, "backup", "--service", service, "--config", file, "--output", output)
			select {
			case <-backup.done:
			case <-time.After(5 * time.Second):
				t.Fatal("native backup instruction attempted a connection")
			}
			if backup.err == nil || !strings.Contains(backup.log.String(), "pg_dump") {
				t.Fatal("PostgreSQL backup did not require native tooling")
			}
			if strings.Contains(backup.log.String(), raw) || strings.Contains(backup.log.String(), "command-secret") {
				t.Fatal("database secret logged by backup")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("PostgreSQL backup created a SQLite artifact")
			}
		})
	}
}

func TestControllerHealthReadsAuthoritativeStore(t *testing.T) {
	const token = "health-administrator-token-32-bytes"
	scope := firewallfleet.Scope{Tenant: "tenant", App: "health"}
	cfg := firewallfleet.Config{StateDir: filepath.Join(t.TempDir(), "fleet"), Token: token, Identities: []firewallfleet.Identity{{ID: "operator", Token: strings.Repeat("a", 32), Scope: scope}}}
	s, err := firewallfleet.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server := httptest.NewServer(fleetHealthHandler(s, cfg))
	defer server.Close()
	c := followClient(t)
	for _, test := range []struct {
		method, path, token string
		want                int
	}{{"GET", "/health", token, 200}, {"GET", "/health", strings.Repeat("a", 32), 200}, {"GET", "/health", "", 401}, {"POST", "/health", token, 405}, {"GET", "/health?scope=foreign", token, 400}} {
		code, raw := followRequest(t, c, test.method, server.URL+test.path, test.token, nil)
		if code != test.want {
			t.Fatalf("health status=%d want=%d", code, test.want)
		}
		if bytes.Contains(raw, []byte(token)) {
			t.Fatal("health disclosed token")
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	code, raw := followRequest(t, c, "GET", server.URL+"/health", token, nil)
	if code != 503 || strings.Contains(string(raw), "sqlite") {
		t.Fatal("closed authoritative database reported healthy or leaked diagnostics")
	}
}

func TestControllerHealthCommand(t *testing.T) {
	const token = "health-command-operator-32-bytes-long"
	t.Setenv("FOLLOW_OPERATOR", token)
	dir := t.TempDir()
	file := followJSON(t, filepath.Join(dir, "controller.json"), serviceFile{StateDir: filepath.Join(dir, "state"), TokenEnv: "FOLLOW_OPERATOR"})
	addr := followAddr(t)
	p := followStart(t, "fleet-controller", "--config", file, "--listen", addr)
	followListen(t, p, addr)
	code, raw := followRequest(t, followClient(t), "GET", "http://"+addr+"/health", token, nil)
	if code != 200 || !bytes.Contains(raw, []byte(`"ready":true`)) {
		t.Fatalf("controller command health status %d", code)
	}
	p.stop(t)
}

func TestNewGatewayProtocolCommands(t *testing.T) {
	for _, protocol := range []string{"mysql", "dnp3"} {
		t.Run(protocol, func(t *testing.T) {
			path := followJSON(t, filepath.Join(t.TempDir(), "policy.json"), followPolicy("gateway-inventory", "false", ""))
			addr := followAddr(t)
			p := followStart(t, "gateway", "--protocol", protocol, "--policy", path, "--listen", addr, "--upstream", "127.0.0.1:9")
			followListen(t, p, addr)
			p.stop(t)
		})
	}
}

func TestPostgresServiceCommandReplicas(t *testing.T) {
	raw := os.Getenv("NETCAP_POSTGRES_TEST_URL")
	if raw == "" {
		t.Skip("NETCAP_POSTGRES_TEST_URL not configured")
	}
	t.Setenv("FOLLOW_DATABASE_URL", raw)
	t.Setenv("FOLLOW_OPERATOR", strings.Repeat("a", 32))
	scope := firewallstate.Scope{Tenant: "tenant", App: "ha"}
	for _, service := range []string{"fleet", "sharedstate"} {
		t.Run(service, func(t *testing.T) {
			namespace := fmt.Sprintf("ncf_cli_%s_%x", service, time.Now().UnixNano())
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				db, err := firewallstate.OpenPostgres(ctx, raw, namespace)
				if err != nil {
					t.Error("PostgreSQL cleanup connection failed")
					return
				}
				defer db.Close()
				if _, err = db.DB.ExecContext(ctx, `DROP SCHEMA "`+namespace+`" CASCADE`); err != nil {
					t.Error("PostgreSQL schema cleanup failed")
				}
			})
			bootstrap := serviceFile{DatabaseURLEnv: "FOLLOW_DATABASE_URL", DatabaseNamespace: namespace}
			command := "fleet-controller"
			health := "/health"
			if service == "fleet" {
				bootstrap.TokenEnv = "FOLLOW_OPERATOR"
			} else {
				command = "sharedstate"
				health = "/api/v1/state/health"
				bootstrap.Principals = []principalFile{{ID: "proxy", TokenEnv: "FOLLOW_OPERATOR", Scope: scope}}
			}
			file := followJSON(t, filepath.Join(t.TempDir(), "service.json"), bootstrap)
			c := followClient(t)
			urls := []string{}
			processes := []*followProcess{}
			for range 2 {
				addr := followAddr(t)
				p := followStart(t, command, "--config", file, "--listen", addr)
				followListen(t, p, addr)
				url := "http://" + addr
				code, _ := followRequest(t, c, "GET", url+health, strings.Repeat("a", 32), nil)
				if code != 200 {
					t.Fatalf("PostgreSQL replica health %d", code)
				}
				urls = append(urls, url)
				processes = append(processes, p)
			}
			if service == "sharedstate" {
				for i, url := range urls {
					code, body := followRequest(t, c, "POST", url+"/api/v1/state/count", strings.Repeat("a", 32), firewallstate.CountRequest{Key: firewallstate.Key{Revision: strings.Repeat("a", 64), Group: strings.Repeat("b", 64)}, Window: firewallstate.Window{Mode: "fixed", Duration: time.Minute}})
					var result firewallstate.CountResult
					if code != 200 || json.Unmarshal(body, &result) != nil || result.Count != int64(i+1) {
						t.Fatal("PostgreSQL CLI replicas did not share counters")
					}
				}
			}
			if service == "fleet" {
				bootstrap.AllowEffects = true
			} else {
				bootstrap.MaxKeys = 128
			}
			mismatchFile := followJSON(t, filepath.Join(t.TempDir(), "mismatch.json"), bootstrap)
			mismatch := followStart(t, command, "--config", mismatchFile, "--listen", followAddr(t))
			select {
			case <-mismatch.done:
			case <-time.After(12 * time.Second):
				t.Fatal("mismatched replica bootstrap did not fail startup")
			}
			if mismatch.err == nil || !strings.Contains(mismatch.log.String(), "matching replica bootstrap") {
				t.Fatal("mismatched replica bootstrap accepted or not redacted")
			}
			if strings.Contains(mismatch.log.String(), raw) {
				t.Fatal("replica mismatch logged database URL")
			}
			for _, p := range processes {
				p.stop(t)
			}
		})
	}
}
