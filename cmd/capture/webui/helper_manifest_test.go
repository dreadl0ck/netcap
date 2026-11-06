//go:build !appstore

package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPackagedHelperManifest(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "go.mod"), []byte("module github.com/dreadl0ck/netcap\n\ngo 1.24\n"), 0600)
	if err := os.MkdirAll(filepath.Join(root, "cmd", "net"), 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "cmd", "net", "main.go"), []byte("package main\nfunc main() { panic(\"must never execute during verification\") }\n"), 0600)
	helper := filepath.Join(root, helperName())
	flags := "-X github.com/dreadl0ck/netcap.Version=v1.2.3 -X github.com/dreadl0ck/netcap.Commit=abc123"
	cmd := exec.Command("go", "build", "-tags", "production,nodpi", "-ldflags", flags, "-o", helper, "./cmd/net")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, out)
	}
	data, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	manifest := helperManifest{1, "github.com/dreadl0ck/netcap", "v1.2.3", "abc123", hex.EncodeToString(hash[:])}
	receipt, _ := json.Marshal(manifest)
	write(helper+".manifest.json", receipt, 0600)
	if err := verifyPackagedHelper(helper, "v1.2.3", "abc123"); err != nil {
		t.Fatal(err)
	}
	t.Run("universal macOS", func(t *testing.T) {
		lipo, err := exec.LookPath("lipo")
		if err != nil {
			t.Skip("lipo is unavailable")
		}
		var slices []string
		for _, arch := range []string{"arm64", "amd64"} {
			slice := filepath.Join(root, "net-"+arch)
			cmd := exec.Command("go", "build", "-tags", "production,nodpi", "-ldflags", flags, "-o", slice, "./cmd/net")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("cross-build: %v: %s", err, out)
			}
			slices = append(slices, slice)
		}
		fat := filepath.Join(root, "universal")
		cmd := exec.Command(lipo, "-create", slices[0], slices[1], "-output", fat)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("lipo: %v: %s", err, out)
		}
		bytes, err := os.ReadFile(fat)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(bytes)
		fatManifest := manifest
		fatManifest.SHA256 = hex.EncodeToString(hash[:])
		encoded, _ := json.Marshal(fatManifest)
		write(fat+".manifest.json", encoded, 0600)
		if err := verifyPackagedHelper(fat, "v1.2.3", "abc123"); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command("go", "build", "-tags", "production,nodpi", "-ldflags", "-X github.com/dreadl0ck/netcap.Version=stale", "-o", slices[0], "./cmd/net")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("stale cross-build: %v: %s", err, out)
		}
		cmd = exec.Command(lipo, "-create", slices[0], slices[1], "-output", fat)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("stale lipo: %v: %s", err, out)
		}
		bytes, err = os.ReadFile(fat)
		if err != nil {
			t.Fatal(err)
		}
		hash = sha256.Sum256(bytes)
		fatManifest.SHA256 = hex.EncodeToString(hash[:])
		encoded, _ = json.Marshal(fatManifest)
		write(fat+".manifest.json", encoded, 0600)
		if verifyPackagedHelper(fat, "v1.2.3", "abc123") == nil {
			t.Fatal("accepted stale universal slice with matching file hash")
		}
	})
	for _, identity := range [][2]string{{"", ""}, {"v0.0.1", "abc123"}, {"v1.2.3", "stale"}} {
		if err := verifyPackagedHelper(helper, identity[0], identity[1]); err == nil {
			t.Fatal("accepted missing/stale identity")
		}
	}
	t.Run("missing manifest preserves helper", func(t *testing.T) {
		if err := os.Rename(helper+".manifest.json", helper+".saved"); err != nil {
			t.Fatal(err)
		}
		defer os.Rename(helper+".saved", helper+".manifest.json")
		if verifyPackagedHelper(helper, "v1.2.3", "abc123") == nil {
			t.Fatal("accepted missing manifest")
		}
		if _, err := os.Stat(helper); err != nil {
			t.Fatal("genuine helper was removed", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(root, "linked")
		if err := os.Symlink(helper, link); err != nil {
			t.Skip(err)
		}
		if verifyPackagedHelper(link, "v1.2.3", "abc123") == nil {
			t.Fatal("accepted symlink")
		}
	})
	t.Run("modified binary", func(t *testing.T) {
		write(helper, append(append([]byte{}, data...), 'x'), 0700)
		defer write(helper, data, 0700)
		if verifyPackagedHelper(helper, "v1.2.3", "abc123") == nil {
			t.Fatal("accepted modified binary")
		}
	})
	t.Run("version spoof with matching receipt", func(t *testing.T) {
		fake := []byte("#!/bin/sh\necho v1.2.3 abc123\n")
		write(helper, fake, 0700)
		defer write(helper, data, 0700)
		hash := sha256.Sum256(fake)
		spoof := manifest
		spoof.SHA256 = hex.EncodeToString(hash[:])
		encoded, _ := json.Marshal(spoof)
		write(helper+".manifest.json", encoded, 0600)
		defer write(helper+".manifest.json", receipt, 0600)
		if verifyPackagedHelper(helper, "v1.2.3", "abc123") == nil {
			t.Fatal("accepted version spoof")
		}
	})
}

func TestProductionHelperNeverSearchesPATH(t *testing.T) {
	old, version, revision := productionPro, proHelperVersion, proHelperRevision
	t.Cleanup(func() { productionPro, proHelperVersion, proHelperRevision = old, version, revision })
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, helperName()), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	SetProductionHelperIdentity("", "")
	if got := resolveHelperExecutable(); got != "" {
		t.Fatalf("production accepted shadow PATH: %s", got)
	}
	productionPro = false
	if runtime.GOOS != "windows" && resolveHelperExecutable() == "" {
		t.Fatal("standalone developer PATH lookup was restricted")
	}
}

func TestPackagedHelperLayouts(t *testing.T) {
	for _, tc := range []struct{ executable, platform, want string }{
		{"/Applications/NETCAP.app/Contents/MacOS/netcap-pro", "darwin", "/Applications/NETCAP.app/Contents/Resources/bin/net"},
		{"/usr/local/bin/netcap-pro", "linux", "/usr/lib/netcap-pro/net"},
		{"/tmp/dev/netcap-pro", "linux", "/tmp/dev/net"},
	} {
		if got := packagedHelperPath(tc.executable, tc.platform); got != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
}
