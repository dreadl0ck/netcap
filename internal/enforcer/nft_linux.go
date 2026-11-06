//go:build linux

package enforcer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NFTBackend exclusively owns one inet table inside an explicitly named network
// namespace. It needs iproute2, nft and namespace administration privileges.
// Construction takes a root-owned /run/netcap-enforcer lock keyed by namespace
// device/inode and inet table, independent of Config.StateFile and scope. No
// commands run until the first List creates the table. Close releases the lock;
// process death also releases it. Never unlink the lock file.
// All cooperating processes must share the host's /run mount; private /run mounts
// cannot coordinate flock ownership and must not target the same network namespace.
type NFTBackend struct {
	mu            sync.Mutex
	config        Config
	nft, ip       string
	namespaceInfo os.FileInfo
	run           func(context.Context, []string, string) ([]byte, error)
	lock          *os.File
	closed        bool
	claimed       bool
}

func NewNFTBackend(config Config) (*NFTBackend, error) {
	c, _, err := normalize(config)
	if err != nil {
		return nil, err
	}
	if c.DryRun {
		return nil, errors.New("NFTBackend cannot be used in dry-run mode")
	}
	if !identifier.MatchString(c.Namespace) {
		return nil, errors.New("explicit named network namespace required")
	}
	p := filepath.Join("/run/netns", c.Namespace)
	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("namespace must be a regular netns bind mount, not a symlink")
	}
	for _, host := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		h, e := os.Stat(host)
		if e != nil {
			return nil, e
		}
		if os.SameFile(info, h) {
			return nil, errors.New("refusing current or PID 1 network namespace")
		}
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return nil, err
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		return nil, err
	}
	b := &NFTBackend{config: c, nft: nft, ip: ip, namespaceInfo: info}
	b.lock, err = lockNFT(info, c.Table)
	if err != nil {
		return nil, err
	}
	b.run = b.execute
	return b, nil
}

func (b *NFTBackend) claim() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("nft backend closed")
	}
	if b.claimed {
		return errors.New("nft backend already belongs to a controller")
	}
	b.claimed = true
	return nil
}

// Close releases singleton ownership without changing kernel leases or the table.
func (b *NFTBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	if b.lock != nil {
		return b.lock.Close()
	}
	return nil
}

func (b *NFTBackend) execute(ctx context.Context, args []string, stdin string) ([]byte, error) {
	info, err := os.Lstat(filepath.Join("/run/netns", b.config.Namespace))
	if err != nil || !os.SameFile(info, b.namespaceInfo) {
		return nil, errors.New("network namespace identity changed")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	argv := append([]string{"netns", "exec", b.config.Namespace, b.nft}, args...)
	cmd := exec.CommandContext(ctx, b.ip, argv...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		return nil, &ExecutionError{fmt.Errorf("nft operation failed: %w", err)}
	}
	return stdout.Bytes(), nil
}

func (b *NFTBackend) owner() string { return "netcap-enforcer-v1:" + fingerprint(b.config) }
func setName(id string) string {
	h := sha256.Sum256([]byte(id))
	return "lease_" + hex.EncodeToString(h[:16])
}
func quote(s string) string { return strconv.Quote(s) }

func (b *NFTBackend) setup() string {
	c := b.config
	return fmt.Sprintf("add table inet %s { comment %s; }\nadd chain inet %s leases { type filter hook %s priority 0; policy accept; }\n", c.Table, quote(b.owner()), c.Table, c.Scope.Hook)
}

type nftObject struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Comment  string `json:"comment"`
	Handle   uint64 `json:"handle"`
	Hook     string `json:"hook"`
	Type     string `json:"type"`
	Policy   string `json:"policy"`
	Priority int    `json:"prio"`
}
type nftDocument struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}
type nftLease struct {
	Lease  Lease
	Handle uint64
}

func (b *NFTBackend) list(ctx context.Context) ([]nftLease, error) {
	if b.closed {
		return nil, errors.New("nft backend closed")
	}
	// A failed list is never interpreted as an absent table. Query the complete
	// table inventory first, then use exclusive `create` semantics on absence.
	data, err := b.run(ctx, []string{"-j", "list", "tables"}, "")
	if err != nil {
		return nil, err
	}
	var doc nftDocument
	if err = json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	exists := false
	for _, entry := range doc.NFTables {
		if raw, ok := entry["table"]; ok {
			var t nftObject
			if err = json.Unmarshal(raw, &t); err != nil {
				return nil, err
			}
			if t.Family == "inet" && t.Name == b.config.Table {
				exists = true
			}
		}
	}
	if !exists {
		// `create table` fails if another owner races the inventory check.
		script := strings.Replace(b.setup(), "add table ", "create table ", 1)
		if _, err = b.run(ctx, []string{"-f", "-"}, script); err != nil {
			return nil, err
		}
	}
	data, err = b.run(ctx, []string{"-j", "list", "table", "inet", b.config.Table}, "")
	if err != nil {
		return nil, err
	}
	return b.decode(data)
}

func (b *NFTBackend) decode(data []byte) ([]nftLease, error) {
	var doc nftDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	owned, chain := false, false
	sets := make(map[string]Lease)
	rules := make(map[string]uint64)
	for _, entry := range doc.NFTables {
		for kind, raw := range entry {
			if kind == "metainfo" {
				continue
			}
			var o nftObject
			if err := json.Unmarshal(raw, &o); err != nil {
				return nil, err
			}
			switch kind {
			case "table":
				if o.Family != "inet" || o.Name != b.config.Table || o.Comment != b.owner() {
					return nil, errors.New("nft table ownership collision")
				}
				owned = true
			case "chain":
				if chain || o.Name != "leases" || o.Hook != b.config.Scope.Hook || o.Type != "filter" || o.Policy != "accept" || o.Priority != 0 {
					return nil, errors.New("unexpected owned chain")
				}
				chain = true
			case "set":
				l, err := b.parseMetadata(o.Comment)
				if err != nil {
					return nil, err
				}
				if o.Name != setName(l.ID) {
					return nil, errors.New("set identity mismatch")
				}
				if _, ok := sets[l.ID]; ok {
					return nil, ErrConflict
				}
				sets[l.ID] = l
			case "rule":
				id := strings.TrimPrefix(o.Comment, "netcap-lease:")
				if !identifier.MatchString(id) || o.Comment != "netcap-lease:"+id || o.Handle == 0 {
					return nil, errors.New("unexpected owned rule")
				}
				if _, ok := rules[id]; ok {
					return nil, ErrConflict
				}
				rules[id] = o.Handle
			default:
				return nil, fmt.Errorf("unexpected nft object %q", kind)
			}
		}
	}
	if !owned || !chain || len(rules) != len(sets) {
		return nil, errors.New("incomplete owned table")
	}
	out := make([]nftLease, 0, len(sets))
	for id, l := range sets {
		h, ok := rules[id]
		if !ok {
			return nil, errors.New("lease rule missing")
		}
		out = append(out, nftLease{l, h})
	}
	return out, nil
}

func metadata(l Lease) string {
	return fmt.Sprintf("nc1|%s|%s|%d|%d", l.ID, l.Source, l.TTLSeconds, l.ExpiresAt.UnixNano())
}
func (b *NFTBackend) parseMetadata(s string) (Lease, error) {
	p := strings.Split(s, "|")
	if len(p) != 5 || p[0] != "nc1" {
		return Lease{}, errors.New("unowned lease set")
	}
	ttl, e := strconv.ParseInt(p[3], 10, 64)
	if e != nil {
		return Lease{}, e
	}
	expiry, e := strconv.ParseInt(p[4], 10, 64)
	if e != nil {
		return Lease{}, e
	}
	l := Lease{ID: p[1], Source: p[2], Scope: b.config.Scope, TTLSeconds: ttl, ExpiresAt: time.Unix(0, expiry).UTC()}
	_, protected, e := normalize(b.config)
	if e != nil {
		return Lease{}, e
	}
	c := Controller{config: b.config, protected: protected}
	if e = c.validate(l); e != nil {
		return Lease{}, e
	}
	return l, nil
}

func (b *NFTBackend) applyScript(l Lease, now time.Time) (string, error) {
	_, protected, err := normalize(b.config)
	if err != nil {
		return "", err
	}
	c := Controller{config: b.config, protected: protected}
	if err = c.validate(l); err != nil {
		return "", err
	}
	remaining := l.ExpiresAt.Sub(now).Milliseconds()
	if remaining < 1 {
		return "", nil
	}
	family, kind := "ip", "ipv4_addr"
	a, _ := netip.ParseAddr(l.Source)
	if a.Is6() {
		family, kind = "ip6", "ipv6_addr"
	}
	table, set := b.config.Table, setName(l.ID)
	s := b.config.Scope
	return fmt.Sprintf("add set inet %s %s { type %s; flags timeout; timeout %dms; comment %s; elements = { %s timeout %dms }; }\nadd rule inet %s leases iifname %s %s daddr %s %s saddr @%s %s dport %d counter drop comment %s\n", table, set, kind, remaining, quote(metadata(l)), l.Source, remaining, table, quote(s.Interface), family, s.DestinationCIDR, family, set, s.Protocol, s.Port, quote("netcap-lease:"+l.ID)), nil
}

func (b *NFTBackend) List(ctx context.Context) ([]Lease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ls, err := b.list(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Lease, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Lease)
	}
	return out, nil
}
func (b *NFTBackend) Apply(ctx context.Context, l Lease) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("nft backend closed")
	}
	// Validate before even creating an empty owned table.
	script, err := b.applyScript(l, time.Now())
	if err != nil || script == "" {
		return err
	}
	ls, err := b.list(ctx)
	if err != nil {
		return err
	}
	for _, old := range ls {
		if old.Lease.ID == l.ID {
			if old.Lease == l {
				return nil
			}
			return ErrConflict
		}
		if old.Lease.Source == l.Source && old.Lease.ExpiresAt.After(time.Now()) {
			return ErrConflict
		}
	}
	// Listing may take time: recompute, never extend, the absolute deadline.
	script, err = b.applyScript(l, time.Now())
	if err != nil || script == "" {
		return err
	}
	_, err = b.run(ctx, []string{"-f", "-"}, script)
	return err
}
func (b *NFTBackend) Delete(ctx context.Context, l Lease) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	ls, err := b.list(ctx)
	if err != nil {
		return err
	}
	for _, old := range ls {
		if old.Lease.ID == l.ID {
			if old.Lease != l {
				return ErrConflict
			}
			script := fmt.Sprintf("delete rule inet %s leases handle %d\ndelete set inet %s %s\n", b.config.Table, old.Handle, b.config.Table, setName(l.ID))
			_, err = b.run(ctx, []string{"-f", "-"}, script)
			return err
		}
	}
	return nil
}
