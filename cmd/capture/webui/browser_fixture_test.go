//go:build !appstore

package webui

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
