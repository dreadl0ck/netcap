package firewall_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/cmd/firewall"
	"github.com/urfave/cli/v3"
)

// Mount the same command as cmd/net, without importing capture's CGO tree.
func runRoot(ctx context.Context, args ...string) (string, error) {
	var output bytes.Buffer
	root := &cli.Command{Name: "net", Writer: &output, ErrWriter: &output, Commands: []*cli.Command{firewall.GetCommand()}}
	err := root.Run(ctx, append([]string{"net", "firewall"}, args...))
	return output.String(), err
}

func TestRootFirewallVersion(t *testing.T) {
	out, err := runRoot(t.Context(), "version")
	if err != nil {
		t.Fatal(err)
	}
	var version struct {
		Version, Policy string
		Protocols       []string
	}
	if err := json.Unmarshal([]byte(out), &version); err != nil {
		t.Fatal(err)
	}
	if version.Version != "netcap-firewall/v1" || version.Policy != "netcap-policy/v1" || strings.Join(version.Protocols, ",") != "http,modbus,dns" {
		t.Fatalf("version contract: %s", out)
	}
}

func TestRootFirewallValidateRelativePolicy(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("version: netcap-policy/v1\nid: cli-relative\nmode: enforce\ndefault: allow\nrules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "runtime.yaml")
	runtime := "version: netcap-firewall/v1\nlisten: '127.0.0.1:0'\nadminListen: '127.0.0.1:0'\nupstream: http://127.0.0.1:1\npolicyFile: policy.yaml\nmaxBodyBytes: 1024\nmaxResponseBytes: 1024\nmaxConcurrent: 2\nbodyTimeout: 1s\n"
	if err := os.WriteFile(config, []byte(runtime), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t.Context(), "validate", "--config", config)
	if err != nil || !strings.Contains(out, "valid policy revision") {
		t.Fatalf("relative policy: %v: %s", err, out)
	}
	if err := os.WriteFile(policy, []byte("version: [invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := runRoot(t.Context(), "validate", "--config", config); err == nil {
		t.Fatalf("malformed policy accepted: %s", out)
	}
}

func TestRootFirewallHealthcheck(t *testing.T) {
	for _, status := range []int{200, 302, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect-target" {
					w.WriteHeader(200)
					return
				}
				if r.Method != "GET" || r.URL.Path != "/readyz" {
					t.Errorf("healthcheck request: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", "/redirect-target")
				w.WriteHeader(status)
			}))
			defer srv.Close()
			_, err := runRoot(t.Context(), "healthcheck", "--url", srv.URL+"/readyz")
			if status == 200 && err != nil {
				t.Fatal(err)
			}
			if status != 200 && (err == nil || !strings.Contains(err.Error(), fmt.Sprint(status))) {
				t.Fatalf("healthcheck status %d: %v", status, err)
			}
		})
	}
}

func TestRootFirewallHealthcheckCancellation(t *testing.T) {
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := runRoot(ctx, "healthcheck", "--url", srv.URL); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("healthcheck did not issue request")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("canceled healthcheck: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("healthcheck ignored cancellation")
	}
}
