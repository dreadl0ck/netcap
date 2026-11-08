//go:build linux && integration

package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNFTSingletonProcess(t *testing.T) {
	if raw := os.Getenv("ENFORCER_SINGLETON_CONFIG"); raw != "" {
		var cfg Config
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatal(err)
		}
		c, err := New(cfg, nil)
		if os.Getenv("ENFORCER_SINGLETON_EXPECT") == "busy" {
			if err == nil {
				_ = c.Close()
				t.Fatal("second controller acquired nft table")
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) || !strings.Contains(err.Error(), "nft namespace/table ownership unavailable") {
				t.Fatalf("expected nft singleton contention, got %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("ENFORCER_SINGLETON_EXPECT") == "crash" {
			os.Exit(0)
		}
		if err = c.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("ENFORCER_NETNS_TEST") != "1" {
		t.Skip("requires disposable privileged Linux lab")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}
	for _, name := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ns := "ncs_" + strconv.Itoa(os.Getpid())
	for _, name := range []string{ns, ns + "other"} {
		if out, err := exec.CommandContext(ctx, "ip", "netns", "add", name).CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	}
	// A second bind-mounted name of the same nsfs inode must use the same lock.
	alias := ns + "alias"
	aliasPath := filepath.Join("/run/netns", alias)
	f, err := os.OpenFile(aliasPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err = syscall.Mount(filepath.Join("/run/netns", ns), aliasPath, "", syscall.MS_BIND, ""); err != nil {
		_ = os.Remove(aliasPath)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(aliasPath, 0); _ = os.Remove(aliasPath) })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := func(t *testing.T, cfg Config, expect string) {
		t.Helper()
		raw, e := json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNFTSingletonProcess$")
		cmd.Env = append(os.Environ(), "ENFORCER_SINGLETON_CONFIG="+string(raw), "ENFORCER_SINGLETON_EXPECT="+expect)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("child expected %s: %v: %s", expect, e, out)
		}
	}
	cfg := testConfig()
	cfg.DryRun = false
	cfg.Namespace = ns
	for _, persisted := range []bool{false, true} {
		name := "no-state"
		if persisted {
			name = "with-state"
		}
		t.Run(name, func(t *testing.T) {
			ownerCfg := cfg
			if persisted {
				ownerCfg.StateFile = filepath.Join(t.TempDir(), "owner.json")
			}
			c := controller(t, ownerCfg, nil)
			l, e := c.Create(ctx, "owned", "198.51.100.1", time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			for _, state := range []string{"", ownerCfg.StateFile, filepath.Join(t.TempDir(), "different.json")} {
				candidate := ownerCfg
				candidate.StateFile = state
				child(t, candidate, "busy")
			}
			aliased := ownerCfg
			aliased.Namespace = alias
			aliased.StateFile = ""
			child(t, aliased, "busy")
			changedScope := ownerCfg
			changedScope.Scope.Protocol = "udp"
			changedScope.StateFile = ""
			child(t, changedScope, "busy")
			ls, e := c.List(ctx)
			if e != nil || len(ls) != 1 || ls[0] != l {
				t.Fatal("contender changed owner's lease", ls, e)
			}
			other := cfg
			other.Table = "netcap_firewall_independent"
			child(t, other, "acquire")
			other = cfg
			other.Namespace = ns + "other"
			child(t, other, "acquire")
			// Reusing an already attached object must not bypass singleton ownership.
			if second, e := New(ownerCfg, c.backend); e == nil {
				_ = second.Close()
				t.Fatal("shared NFTBackend accepted")
			}
			child(t, ownerCfg, "busy")
			if ls, e := c.List(ctx); e != nil || len(ls) != 1 || ls[0] != l {
				t.Fatal("rejected backend reuse damaged owner", ls, e)
			}
			if e = c.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = c.backend.List(ctx); e == nil {
				t.Fatal("closed backend still usable")
			}
			child(t, ownerCfg, "acquire")
			candidate := ownerCfg
			candidate.StateFile = filepath.Join(t.TempDir(), "after-close.json")
			child(t, candidate, "acquire")
		})
	}
	crashCfg := cfg
	crashCfg.StateFile = filepath.Join(t.TempDir(), "crash.json")
	child(t, crashCfg, "crash")
	recovered := controller(t, crashCfg, nil)
	if err = recovered.Close(); err != nil {
		t.Fatal(err)
	}
	// Constructor failures after acquiring the NFT lock must release it too.
	bad := cfg
	bad.StateFile = filepath.Join(t.TempDir(), "missing", "state.json")
	if c, e := New(bad, nil); e == nil {
		_ = c.Close()
		t.Fatal("invalid state parent accepted")
	}
	child(t, cfg, "acquire")
	bad = cfg
	bad.StateFile = filepath.Join(t.TempDir(), "corrupt.json")
	if err = os.WriteFile(bad.StateFile, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if c, e := New(bad, nil); e == nil {
		_ = c.Close()
		t.Fatal("corrupt state accepted")
	}
	child(t, cfg, "acquire")
	// A failed ownership check after lock acquisition must not leak the singleton.
	bad = cfg
	bad.Scope.Port++
	if c, e := New(bad, nil); e == nil {
		_ = c.Close()
		t.Fatal("mismatched table scope accepted")
	}
	child(t, cfg, "acquire")
	direct, err := NewNFTBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	child(t, cfg, "busy")
	if err = direct.Close(); err != nil {
		t.Fatal(err)
	}
	child(t, cfg, "acquire")
	// The canonical lock file cannot be redirected or precreated with unsafe
	// permissions/hard links, even by a cooperating privileged launcher.
	unsafeCfg := cfg
	unsafeCfg.Table = "netcap_firewall_lockpath"
	info, err := os.Stat(filepath.Join("/run/netns", ns))
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	lockPath := filepath.Join("/run", nftLockDirectory, fmt.Sprintf("net-%x-%x-inet-%s.lock", stat.Dev, stat.Ino, unsafeCfg.Table))
	backing := filepath.Join(t.TempDir(), "backing")
	if err = os.WriteFile(backing, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(backing, lockPath); err != nil {
		t.Fatal(err)
	}
	if b, e := NewNFTBackend(unsafeCfg); e == nil {
		_ = b.Close()
		t.Fatal("symlink lock accepted")
	}
	if err = os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(lockPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if b, e := NewNFTBackend(unsafeCfg); e == nil {
		_ = b.Close()
		t.Fatal("non-private lock accepted")
	}
	if err = os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(backing, lockPath); err != nil {
		t.Fatal(err)
	}
	if b, e := NewNFTBackend(unsafeCfg); e == nil {
		_ = b.Close()
		t.Fatal("hard-linked lock accepted")
	}
	if err = os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	child(t, unsafeCfg, "acquire")
	t.Log("cross-process nft singleton verified: same/different/no state, namespace alias, changed scope, independent namespace/table, Close/crash release, constructor-failure cleanup")
}
