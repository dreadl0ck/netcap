//go:build !appstore

package webui

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isolateBrowserFixture(t *testing.T) {
	t.Helper()
	if os.Getenv("PLAYWRIGHT_BROWSERS_PATH") == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("PLAYWRIGHT_BROWSERS_PATH", filepath.Join(cache, "ms-playwright"))
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "NC_") || strings.HasPrefix(name, "NETCAP_") {
			t.Setenv(name, "")
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("NC_CONFIG_ROOT", filepath.Join(home, "config", "netcap"))
}

func browserFixtureEnvironment(t *testing.T, output string) []string {
	t.Helper()
	home := t.TempDir()
	env := []string{"HOME=" + home, "USERPROFILE=" + home, "NC_CONFIG_ROOT=" + filepath.Join(home, "config"), "NETCAP_BROWSER_OUTPUT=" + output}
	for _, name := range []string{"PATH", "TMPDIR", "TMP", "TEMP", "SystemRoot", "CHROME_PATH", "PLAYWRIGHT_BROWSERS_PATH"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	evidence, err := os.MkdirTemp(os.TempDir(), "netcap-browser-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("browser evidence: %s", evidence)
	return append(env, "NETCAP_BROWSER_EVIDENCE="+evidence)
}

func TestServerStartOwnsListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := NewServer(listener.Addr().String(), t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := server.Start(); err == nil {
		t.Fatal("Start accepted an occupied port")
	}
}

func TestServerStopPreservesUnrelatedListener(t *testing.T) {
	isolateBrowserFixture(t)
	unrelated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "unrelated-owner")
	}))
	defer unrelated.Close()
	failed := NewServer(unrelated.Listener.Addr().String(), t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := failed.Start(); err == nil {
		t.Fatal("occupied listener accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := failed.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	owned := NewServer("127.0.0.1:0", t.TempDir(), nil, "", false, false, false, nil, nil, false)
	if err := owned.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owned.Stop(context.Background()) })
	client := &http.Client{Timeout: time.Second}
	ready, err := client.Get(owned.GetURL() + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(ready.Body)
	ready.Body.Close()
	if err != nil || !strings.Contains(string(data), owned.outDir) {
		t.Fatalf("owned server identity missing: %s %v", data, err)
	}
	if err := owned.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", owned.addr)
	if err != nil {
		t.Fatalf("owned port not released: %v", err)
	}
	defer listener.Close()
	response, err := client.Get(unrelated.URL)
	if err != nil {
		t.Fatalf("cleanup stopped unrelated server: %v", err)
	}
	defer response.Body.Close()
	data, err = io.ReadAll(response.Body)
	if err != nil || string(data) != "unrelated-owner" {
		t.Fatalf("unrelated identity changed: %q %v", data, err)
	}
}
