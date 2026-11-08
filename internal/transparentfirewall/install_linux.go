//go:build linux

package transparentfirewall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const tableName = "netcap_transparentfirewall"

var errOwnerChanged = errors.New("owned table identity changed; refusing cleanup")

// Install probes an existing listener in the pinned target namespace before
// atomically creating scoped prerouting DNAT rules. It never launches a process,
// changes routes/sysctls, or installs an output hook. Gateway upstream sockets
// must be created by a gateway process already running in that namespace.
// DNAT targets the first ready unicast ingress address of the service family;
// the gateway must bind that address or a matching wildcard listener.
// The TCP probe checks reachability, not gateway policy or TLS configuration.
// NAT applies to new connections; existing conntrack mappings persist until the
// corresponding sessions close or expire. Cleanup does not flush conntrack.
//
// The returned cleanup is idempotent and uses its own timeout. Call it after
// ctx cancellation; ctx only bounds installation. Cleanup errors retain the lock
// and descriptors for retry. A process crash leaves the owned table in place;
// subsequent installation refuses stale tables rather than silently adopting one.
// A non-nil cleanup may accompany an installation error if rollback failed.
// Cooperating installers must share /run for namespace/table flock ownership.
func Install(ctx context.Context, c Config) (cleanup func() error, result error) {
	c, service, err := normalize(c)
	if err != nil {
		return nil, err
	}
	ns, err := openNamespace(c.NetworkNamespace)
	if err != nil {
		return nil, err
	}
	lock, err := lockNamespace(ns)
	if err != nil {
		ns.Close()
		return nil, err
	}
	defer func() {
		if result != nil && cleanup == nil {
			lock.Close()
			ns.Close()
		}
	}()
	address, err := interfaceAddress(ctx, ns, c.IngressInterface, service.Addr().Is4())
	if err != nil {
		return nil, err
	}
	if err = probe(ctx, ns, address, c.GatewayPort); err != nil {
		return nil, fmt.Errorf("gateway listener not ready in target namespace at %s: %w", netip.AddrPortFrom(address, uint16(c.GatewayPort)), err)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	owner := "netcap-transparent-v1:" + hex.EncodeToString(nonce[:])
	var mu sync.Mutex
	closed := false
	cleanup = func() error {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		data, err := run(ctx, ns, "nft", "", "-j", "list", "tables")
		if err != nil {
			return err
		}
		var doc struct {
			NFTables []struct {
				Table *struct{ Family, Name, Comment string }
			} `json:"nftables"`
		}
		if err = json.Unmarshal(data, &doc); err != nil {
			return err
		}
		found := false
		for _, entry := range doc.NFTables {
			if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == tableName {
				found = true
				if entry.Table.Comment != owner {
					return errOwnerChanged
				}
			}
		}
		if found {
			if _, err = run(ctx, ns, "nft", "delete table inet "+tableName+"\n", "-f", "-"); err != nil {
				return err
			}
		}
		closed = true
		return errors.Join(lock.Close(), ns.Close())
	}
	if _, err = run(ctx, ns, "nft", rules(c, service, address, owner), "-f", "-"); err != nil {
		// A killed nft process may have committed its transaction already.
		// Roll back only our nonce, never a pre-existing table with this name.
		if rollbackErr := cleanup(); rollbackErr != nil && !errors.Is(rollbackErr, errOwnerChanged) {
			return cleanup, errors.Join(err, rollbackErr)
		}
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		if rollbackErr := cleanup(); rollbackErr != nil {
			return cleanup, errors.Join(err, rollbackErr)
		}
		return nil, err
	}
	return cleanup, nil
}

func run(ctx context.Context, ns *os.File, tool, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	argv := append([]string{"--net=/proc/self/fd/3", "--", tool}, args...)
	cmd := exec.CommandContext(ctx, "nsenter", argv...)
	cmd.ExtraFiles = []*os.File{ns}
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("scoped %s: %w: %s", tool, err, out)
	}
	return out, nil
}

func interfaceAddress(ctx context.Context, ns *os.File, name string, v4 bool) (netip.Addr, error) {
	data, err := run(ctx, ns, "ip", "", "-j", "addr", "show", "dev", name)
	if err != nil {
		return netip.Addr{}, err
	}
	var links []struct {
		Flags     []string
		Addresses []struct {
			Local     string
			Flags     []string
			Tentative bool
			DADFailed bool `json:"dadfailed"`
		} `json:"addr_info"`
	}
	if err = json.Unmarshal(data, &links); err != nil {
		return netip.Addr{}, err
	}
	for _, l := range links {
		up := false
		for _, flag := range l.Flags {
			if flag == "UP" {
				up = true
			}
		}
		if !up {
			continue
		}
		for _, entry := range l.Addresses {
			bad := entry.Tentative || entry.DADFailed
			for _, flag := range entry.Flags {
				if flag == "tentative" || flag == "dadfailed" {
					bad = true
				}
			}
			a, e := netip.ParseAddr(entry.Local)
			if e == nil && a.Is4() == v4 && a.IsGlobalUnicast() && !a.Is4In6() && !bad {
				return a, nil
			}
		}
	}
	return netip.Addr{}, errors.New("ingress interface must be up with a ready unicast address matching service family")
}

func rules(c Config, service netip.Prefix, address netip.Addr, owner string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "create table inet %s { comment %s; }\nadd chain inet %s ingress { type nat hook prerouting priority dstnat; policy accept; }\n", tableName, strconv.Quote(owner), tableName)
	prefix := "add rule inet " + tableName + " ingress "
	b.WriteString(prefix + "iifname \"lo\" return\n")
	for _, s := range c.ManagementPeers {
		p, _ := netip.ParsePrefix(s)
		family := "ip6"
		if p.Addr().Is4() {
			family = "ip"
		}
		for _, side := range []string{"saddr", "daddr"} {
			fmt.Fprintf(&b, "%s%s %s %s return\n", prefix, family, side, s)
		}
	}
	family := "ip6"
	if service.Addr().Is4() {
		family = "ip"
	}
	fmt.Fprintf(&b, "%siifname %s %s daddr %s tcp dport %d counter dnat %s to %s\n", prefix, strconv.Quote(c.IngressInterface), family, service, c.OriginalPort, family, netip.AddrPortFrom(address, uint16(c.GatewayPort)))
	return b.String()
}

func openNamespace(name string) (*os.File, error) {
	fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		h, e := os.Stat(path)
		if e != nil {
			return fail(e)
		}
		if os.SameFile(info, h) {
			return fail(errors.New("refusing current or PID 1 network namespace"))
		}
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.NSFS_MAGIC {
		return fail(errors.New("target must be a named network namespace bind mount"))
	}
	return f, nil
}

func lockNamespace(ns *os.File) (*os.File, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(ns.Fd()), &st); err != nil {
		return nil, err
	}
	run, err := unix.Open("/run", unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(run)
	if err = checkNode(run, unix.S_IFDIR, 0); err != nil {
		return nil, err
	}
	if err = unix.Mkdirat(run, "netcap-enforcer", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	dir, err := unix.Openat(run, "netcap-enforcer", unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	if err = checkNode(dir, unix.S_IFDIR, 0700); err != nil {
		return nil, err
	}
	key := fmt.Sprintf("net-%x-%x-inet-%s.lock", st.Dev, st.Ino, tableName)
	fd, err := unix.Openat(dir, key, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), key)
	if err = checkNode(fd, unix.S_IFREG, 0600); err == nil {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("namespace/table ownership unavailable: %w", err)
	}
	return f, nil
}

func checkNode(fd int, kind, mode uint32) error {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return err
	}
	if s.Uid != 0 || s.Mode&unix.S_IFMT != kind || s.Mode&0022 != 0 || (mode != 0 && s.Mode&07777 != mode) || (kind == unix.S_IFREG && s.Nlink != 1) {
		return errors.New("lock path must be root-owned, private, correct type and without hard links")
	}
	return nil
}
