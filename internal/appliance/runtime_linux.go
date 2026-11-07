//go:build linux

package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/dreadl0ck/netcap/internal/networkfirewall"

	"golang.org/x/sys/unix"
)

type journal struct {
	Manifest  Manifest        `json:"manifest"`
	Digest    string          `json:"digest"`
	Pending   string          `json:"pending"`
	Completed map[string]bool `json:"completed"`
	Removed   bool            `json:"removed"`
}
type Observation struct {
	Namespace  string          `json:"namespace"`
	Exists     bool            `json:"exists"`
	Owned      bool            `json:"owned"`
	Error      string          `json:"error,omitempty"`
	Links      json.RawMessage `json:"links"`
	Addresses  json.RawMessage `json:"addresses"`
	IPv4Routes json.RawMessage `json:"ipv4Routes"`
	IPv6Routes json.RawMessage `json:"ipv6Routes"`
	Ruleset    json.RawMessage `json:"ruleset"`
}
type Status struct {
	Plan      Plan            `json:"plan"`
	Pending   string          `json:"pending"`
	Completed map[string]bool `json:"completed"`
	Observed  []Observation   `json:"observed"`
	Removed   bool            `json:"removed"`
}

var command = runCommand

func runCommand(ctx context.Context, args ...string) ([]byte, error) {
	b, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%v: %w: %s", args, err, b)
	}
	return b, nil
}
func scoped(ctx context.Context, n string, args ...string) ([]byte, error) {
	return command(ctx, append([]string{"ip", "netns", "exec", n}, args...)...)
}
func save(dir string, j journal) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".journal-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "desired.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Execute deliberately admits only a disposable container, never a host or
// production node. The persisted desired topology is immutable for its lifetime.
func Execute(ctx context.Context, m Manifest, dir, action string) (any, error) {
	p, err := m.Plan()
	if err != nil {
		return nil, err
	}
	if os.Getenv("NETCAP_APPLIANCE_LAB") != "1" {
		return nil, errors.New("explicit NETCAP_APPLIANCE_LAB=1 disposable container gate required")
	}
	if _, err = os.Stat("/.dockerenv"); err != nil {
		return nil, errors.New("topology writes require a disposable Docker lab")
	}
	if action != "apply" && action != "recover" && action != "remove" && action != "status" {
		return nil, errors.New("unknown appliance action")
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("absolute private state directory required")
	}
	// Reject symlinked or writable ancestors before creating any journal/lock.
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		st, e := os.Lstat(d)
		if e == nil {
			s := st.Sys().(*syscall.Stat_t)
			if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || s.Uid != 0 || st.Mode().Perm()&0022 != 0 {
				return nil, fmt.Errorf("unsafe state ancestor %s", d)
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if d == "/" {
			break
		}
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(dir, "lifetime.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Nlink != 1 || st.Uid != 0 || st.Mode&07777 != 0600 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("unsafe appliance lock")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("appliance lifecycle already owned")
	}
	// One lifecycle owner across state directories in this supervisor netns.
	sock, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(sock)
	if err = unix.Bind(sock, &unix.SockaddrUnix{Name: "@netcap.appliance.lifecycle.v1"}); err != nil {
		return nil, errors.New("kernel lifecycle fence unavailable")
	}
	j := journal{Manifest: m, Digest: p.Digest, Completed: map[string]bool{}}
	data, err := os.ReadFile(filepath.Join(dir, "desired.json"))
	if err == nil {
		if len(data) > MaxManifestBytes*4 {
			return nil, errors.New("journal exceeds bound")
		}
		if err = json.Unmarshal(data, &j); err != nil {
			return nil, err
		}
		if j.Digest != p.Digest {
			return nil, errors.New("immutable topology/nonce mismatch")
		}
		persisted, e := j.Manifest.Plan()
		if e != nil || persisted.Digest != p.Digest || j.Completed == nil {
			return nil, errors.New("corrupt desired topology journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		if action != "apply" {
			return nil, errors.New("no persisted desired topology; refusing adoption")
		}
		// Preflight all namespace names before writing the first resource.
		for _, n := range m.Namespaces {
			if _, e := os.Lstat("/run/netns/" + n); !errors.Is(e, os.ErrNotExist) {
				return nil, fmt.Errorf("namespace %s already exists or is inaccessible", n)
			}
		}
		if err = save(dir, j); err != nil {
			return nil, err
		}
	}
	if j.Removed && action != "status" {
		return nil, errors.New("removed nonce cannot be reused")
	}
	if action == "remove" {
		if err = remove(ctx, m); err != nil {
			return nil, err
		}
		j.Removed = true
		if err = save(dir, j); err != nil {
			return nil, err
		}
	} else if action != "status" {
		reconcile := func(op Operation) error {
			j.Pending = op.ID
			if err = save(dir, j); err != nil {
				return err
			}
			if err = apply(ctx, m, op); err != nil {
				return err
			}
			j.Completed[op.ID] = true
			j.Pending = ""
			if err = save(dir, j); err != nil {
				return err
			}
			return nil
		}
		if _, e := os.Lstat("/run/netns/" + m.Packet.Namespace); errors.Is(e, os.ErrNotExist) {
			for _, op := range p.Operations {
				if op.Kind == "namespace" {
					if err = reconcile(op); err != nil {
						return nil, err
					}
				}
			}
		}
		if err = owned(ctx, m, m.Packet.Namespace); err != nil {
			return nil, err
		}
		if err = networkfirewall.ProvisionOwned(ctx, m.NetworkConfig(), func() error {
			for _, op := range p.Operations {
				if err := reconcile(op); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	s := Status{Plan: p, Pending: j.Pending, Completed: j.Completed, Observed: []Observation{}, Removed: j.Removed}
	if !j.Removed {
		for _, n := range m.Namespaces {
			o := Observation{Namespace: n}
			if _, e := os.Lstat("/run/netns/" + n); errors.Is(e, os.ErrNotExist) {
				s.Observed = append(s.Observed, o)
				continue
			}
			o.Exists = true
			if e := owned(ctx, m, n); e != nil {
				o.Error = e.Error()
				s.Observed = append(s.Observed, o)
				continue
			}
			o.Owned = true
			for _, q := range []struct {
				dest *json.RawMessage
				args []string
			}{{&o.Links, []string{"ip", "-j", "link", "show"}}, {&o.Addresses, []string{"ip", "-j", "addr", "show"}}, {&o.IPv4Routes, []string{"ip", "-j", "route", "show", "table", "all"}}, {&o.IPv6Routes, []string{"ip", "-6", "-j", "route", "show", "table", "all"}}, {&o.Ruleset, []string{"nft", "-j", "list", "ruleset"}}} {
				b, e := scoped(ctx, n, q.args...)
				if e != nil {
					return nil, e
				}
				*q.dest = b
			}
			s.Observed = append(s.Observed, o)
		}
	}
	return s, nil
}

type linkInfo struct {
	Name    string `json:"ifname"`
	Alias   string `json:"ifalias"`
	Address string `json:"address"`
	Info    struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func linkMAC(m Manifest, namespace, name string) string {
	sum := sha256.Sum256([]byte(m.Nonce + "/" + namespace + "/" + name))
	sum[0] = (sum[0] | 2) & 0xfe
	return net.HardwareAddr(sum[:6]).String()
}

func links(ctx context.Context, n string) ([]linkInfo, error) {
	b, e := scoped(ctx, n, "ip", "-d", "-j", "link", "show")
	if e != nil {
		return nil, e
	}
	var l []linkInfo
	e = json.Unmarshal(b, &l)
	return l, e
}
func owned(ctx context.Context, m Manifest, n string) error {
	l, err := links(ctx, n)
	if err != nil {
		return err
	}
	for _, i := range l {
		if i.Name == "lo" && i.Alias == "netcap-appliance:"+m.Nonce {
			return nil
		}
	}
	return fmt.Errorf("namespace %s lacks immutable ownership marker; no automatic cleanup", n)
}
func apply(ctx context.Context, m Manifest, o Operation) error {
	a := o.Arguments
	run := func(args ...string) error { _, e := scoped(ctx, o.Namespace, args...); return e }
	if o.Kind == "namespace" {
		if _, e := os.Lstat("/run/netns/" + o.Namespace); errors.Is(e, os.ErrNotExist) {
			if _, e = command(ctx, "ip", "netns", "add", o.Namespace); e != nil {
				return e
			}
			// The kernel may populate a fresh namespace with fallback tunnel
			// devices. Mark this initial inventory before admitting the namespace.
			initial, e := links(ctx, o.Namespace)
			if e != nil {
				return e
			}
			for _, l := range initial {
				if l.Name != "lo" {
					if e = run("ip", "link", "set", l.Name, "alias", "netcap-appliance:"+m.Nonce); e != nil {
						return e
					}
				}
			}
			if e = run("ip", "link", "set", "lo", "alias", "netcap-appliance:"+m.Nonce); e != nil {
				return e
			}
		}
		if e := owned(ctx, m, o.Namespace); e != nil {
			return e
		}
		return run("ip", "link", "set", "lo", "up")
	}
	if err := owned(ctx, m, o.Namespace); err != nil {
		return err
	}
	switch o.Kind {
	case "packet":
		return nil // ProvisionOwned retains the packet fences around reconciliation.
	case "veth":
		if err := owned(ctx, m, a[1]); err != nil {
			return err
		}
		l, err := links(ctx, o.Namespace)
		if err != nil {
			return err
		}
		for _, i := range l {
			if i.Name == a[0] {
				if i.Address != linkMAC(m, o.Namespace, a[0]) || i.Info.Kind != "veth" || (i.Alias != "" && i.Alias != "netcap-appliance:"+m.Nonce) {
					return errors.New("foreign interface collision")
				}
				return markPair(ctx, m, o.Namespace, a[0], a[1], a[2])
			}
		}
		// Creation installs nonce-derived MAC identities on both peers atomically;
		// iproute2's veth creation silently ignores interface aliases.
		if err := run("ip", "link", "add", a[0], "address", linkMAC(m, o.Namespace, a[0]), "type", "veth", "peer", "name", a[2], "netns", a[1], "address", linkMAC(m, a[1], a[2])); err != nil {
			return err
		}
		return markPair(ctx, m, o.Namespace, a[0], a[1], a[2])
	case "address":
		if err := ownedLink(ctx, m, o.Namespace, a[0]); err != nil {
			return err
		}
		b, err := scoped(ctx, o.Namespace, "ip", "-j", "addr", "show", "dev", a[0])
		if err != nil {
			return err
		}
		var v []struct {
			Addresses []struct {
				Local  string `json:"local"`
				Prefix int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		if err = json.Unmarshal(b, &v); err != nil {
			return err
		}
		for _, i := range v {
			for _, p := range i.Addresses {
				if fmt.Sprintf("%s/%d", p.Local, p.Prefix) == a[1] {
					return nil
				}
			}
		}
		args := []string{"ip", "addr", "add", a[1], "dev", a[0]}
		if strings.Contains(a[1], ":") {
			args = append(args, "nodad")
		}
		return run(args...)
	case "up":
		if err := ownedLink(ctx, m, o.Namespace, a[0]); err != nil {
			return err
		}
		return run("ip", "link", "set", a[0], "up")
	case "route":
		if err := ownedLink(ctx, m, o.Namespace, a[2]); err != nil {
			return err
		}
		family := "-4"
		if strings.Contains(a[0], ":") {
			family = "-6"
		}
		b, err := scoped(ctx, o.Namespace, "ip", family, "-j", "route", "show", a[0])
		if err != nil {
			return err
		}
		var rs []struct {
			Dst      string `json:"dst"`
			Gateway  string `json:"gateway"`
			Dev      string `json:"dev"`
			Protocol any    `json:"protocol"`
		}
		if err = json.Unmarshal(b, &rs); err != nil {
			return err
		}
		if len(rs) > 0 {
			if len(rs) == 1 && rs[0].Dst == a[0] && rs[0].Gateway == a[1] && rs[0].Dev == a[2] && (fmt.Sprint(rs[0].Protocol) == "186" || fmt.Sprint(rs[0].Protocol) == "bgp") {
				return nil
			}
			return errors.New("foreign route collision")
		}
		return run("ip", family, "route", "add", a[0], "via", a[1], "dev", a[2], "proto", "186")
	case "forward":
		return run("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
	}
	return errors.New("unknown operation")
}

func markPair(ctx context.Context, m Manifest, aNS, aName, bNS, bName string) error {
	for _, ep := range [][2]string{{aNS, aName}, {bNS, bName}} {
		ls, err := links(ctx, ep[0])
		if err != nil {
			return err
		}
		found := false
		for _, l := range ls {
			if l.Name == ep[1] && l.Info.Kind == "veth" && l.Address == linkMAC(m, ep[0], ep[1]) && (l.Alias == "" || l.Alias == "netcap-appliance:"+m.Nonce) {
				found = true
			}
		}
		if !found {
			return errors.New("missing or foreign veth peer; refusing adoption")
		}
	}
	for _, ep := range [][2]string{{aNS, aName}, {bNS, bName}} {
		if _, err := scoped(ctx, ep[0], "ip", "link", "set", ep[1], "alias", "netcap-appliance:"+m.Nonce); err != nil {
			return err
		}
	}
	return nil
}

func ownedLink(ctx context.Context, m Manifest, namespace, name string) error {
	ls, err := links(ctx, namespace)
	if err != nil {
		return err
	}
	for _, l := range ls {
		if l.Name == name && l.Alias == "netcap-appliance:"+m.Nonce {
			return nil
		}
	}
	return fmt.Errorf("missing or foreign interface %s/%s", namespace, name)
}

func remove(ctx context.Context, m Manifest) error {
	if _, e := os.Lstat("/run/netns/" + m.Packet.Namespace); e == nil {
		return networkfirewall.RetireOwned(ctx, m.NetworkConfig(), func() error { return removeTopology(ctx, m) })
	}
	return removeTopology(ctx, m)
}

func removeTopology(ctx context.Context, m Manifest) error {
	// Whole-namespace destruction is allowed only for a pristine topology. Foreign
	// links or any nftables table stop removal before the first mutation.
	for _, n := range m.Namespaces {
		if _, e := os.Lstat("/run/netns/" + n); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e := owned(ctx, m, n); e != nil {
			return e
		}
		ls, e := links(ctx, n)
		if e != nil {
			return e
		}
		for _, l := range ls {
			if l.Alias != "netcap-appliance:"+m.Nonce {
				return fmt.Errorf("foreign link %s/%s; preserving topology", n, l.Name)
			}
		}
		b, e := scoped(ctx, n, "nft", "-j", "list", "tables")
		if e != nil {
			return e
		}
		var tables struct {
			NFT []map[string]json.RawMessage `json:"nftables"`
		}
		if e = json.Unmarshal(b, &tables); e != nil {
			return e
		}
		for _, t := range tables.NFT {
			if raw, ok := t["table"]; ok {
				var table struct {
					Family string `json:"family"`
					Name   string `json:"name"`
				}
				if e = json.Unmarshal(raw, &table); e != nil {
					return e
				}
				if n != m.Packet.Namespace || table.Family != "inet" || table.Name != "netcap_networkfirewall" {
					return errors.New("foreign nftables state; preserving topology")
				}
			}
		}
		b, e = command(ctx, "ip", "netns", "pids", n)
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(b)) != "" {
			return errors.New("namespace has live processes; fence services first")
		}
		for _, family := range []string{"-4", "-6"} {
			b, e = scoped(ctx, n, "ip", family, "-j", "route", "show", "table", "all")
			if e != nil {
				return e
			}
			var routes []struct {
				Protocol any    `json:"protocol"`
				Dst      string `json:"dst"`
				Gateway  string `json:"gateway"`
				Dev      string `json:"dev"`
			}
			if e = json.Unmarshal(b, &routes); e != nil {
				return e
			}
			for _, r := range routes {
				p := fmt.Sprint(r.Protocol)
				if p == "186" || p == "bgp" {
					match := false
					for _, want := range m.Routes {
						if want.Namespace == n && want.Destination == r.Dst && want.Via == r.Gateway && want.Interface == r.Dev {
							match = true
						}
					}
					if !match {
						return errors.New("undeclared protocol-186 route; preserving topology")
					}
				} else if p != "kernel" {
					return errors.New("foreign routes; preserving topology")
				}
			}
		}
		if e := checkForeignAddresses(ctx, m, n); e != nil {
			return e
		}
	}
	for i := len(m.Namespaces) - 1; i >= 0; i-- {
		n := m.Namespaces[i]
		if _, e := os.Lstat("/run/netns/" + n); errors.Is(e, os.ErrNotExist) {
			continue
		}
		if _, e := command(ctx, "ip", "netns", "del", n); e != nil {
			return e
		}
	}
	return nil
}

func checkForeignAddresses(ctx context.Context, m Manifest, n string) error {
	b, e := scoped(ctx, n, "ip", "-j", "addr", "show")
	if e != nil {
		return e
	}
	var addresses []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if e = json.Unmarshal(b, &addresses); e != nil {
		return e
	}
	for _, iface := range addresses {
		for _, addr := range iface.Addresses {
			if iface.Name == "lo" && (addr.Local == "127.0.0.1" || addr.Local == "::1") || addr.Scope == "link" && strings.HasPrefix(addr.Local, "fe80:") {
				continue
			}
			match := false
			for _, pair := range m.Links {
				for _, ep := range []Endpoint{pair.A, pair.B} {
					if ep.Namespace == n && ep.Interface == iface.Name {
						for _, cidr := range ep.CIDRs {
							if cidr == fmt.Sprintf("%s/%d", addr.Local, addr.Prefix) {
								match = true
							}
						}
					}
				}
			}
			if !match {
				return errors.New("foreign address; preserving topology")
			}
		}
	}
	for _, family := range []string{"-4", "-6"} {
		b, e = scoped(ctx, n, "ip", family, "-j", "rule", "show")
		if e != nil {
			return e
		}
		var rules []struct {
			Priority int `json:"priority"`
			Table    any `json:"table"`
		}
		if e = json.Unmarshal(b, &rules); e != nil {
			return e
		}
		for _, r := range rules {
			if !((r.Priority == 0 && fmt.Sprint(r.Table) == "local") || (r.Priority == 32766 && fmt.Sprint(r.Table) == "main") || (r.Priority == 32767 && fmt.Sprint(r.Table) == "default")) {
				return errors.New("foreign routing policy; preserving topology")
			}
		}
		b, e = scoped(ctx, n, "ip", family, "-j", "neigh", "show")
		if e != nil {
			return e
		}
		var neighbors []struct {
			State []string `json:"state"`
		}
		if e = json.Unmarshal(b, &neighbors); e != nil {
			return e
		}
		for _, v := range neighbors {
			for _, state := range v.State {
				if state == "PERMANENT" || state == "NOARP" {
					return errors.New("foreign static neighbor; preserving topology")
				}
			}
		}
	}
	return nil
}
