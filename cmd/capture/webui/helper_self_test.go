//go:build !appstore

package webui

import (
	"reflect"
	"testing"
)

func TestStandaloneHelperCommandPreservesLoaderAndImage(t *testing.T) {
	for _, tc := range []struct {
		executable, platform, candidate string
		prefix                          []string
	}{
		{"/package with spaces/lib/ld-linux-x86-64.so.2", "linux", "/package with spaces/lib/net.bin", []string{"--library-path", "/package with spaces/lib", "/package with spaces/lib/net.bin"}},
		{"/usr/local/bin/netcap", "linux", "/usr/local/bin/netcap", nil},
		{"/Applications/Netcap/net", "darwin", "/Applications/Netcap/net", nil},
	} {
		seen := ""
		command, prefix := standaloneCommand(tc.executable, tc.platform, func(path string) bool { seen = path; return true })
		if command != tc.executable || seen != tc.candidate || !reflect.DeepEqual(prefix, tc.prefix) {
			t.Fatal(command, prefix, seen)
		}
		command, _ = standaloneCommand(tc.executable, tc.platform, func(string) bool { return false })
		if command != "" {
			t.Fatal("unverified image selected a helper")
		}
	}
}
