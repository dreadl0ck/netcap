//go:build linux

package networkfirewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

const tableName = "netcap_networkfirewall"

func netipPrefix(s string) (string, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", err
	}
	if p.Addr().Is4() {
		return "ip", nil
	}
	return "ip6", nil
}

// Run is single-use. Netlink's NetNS option creates the socket in the pinned
// namespace; nsenter inherits that same descriptor for nft operations. Neither
// operation depends on the Go scheduler's current OS thread namespace.
func (f *Firewall) Run(ctx context.Context) (result error) {
	if !f.started.CompareAndSwap(false, true) {
		return errors.New("firewall Run is single-use")
	}
	ns, err := openNamespace(f.config.Namespace)
	if err != nil {
		return err
	}
	defer ns.Close()
	fence, err := kernelFence(ns)
	if err != nil {
		return err
	}
	defer unix.Close(fence)
	lock, err := lockNamespace(ns, fence)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err = exec.LookPath("nsenter"); err != nil {
		return err
	}
	if _, err = exec.LookPath("nft"); err != nil {
		return err
	}
	check := exec.CommandContext(ctx, "nsenter", "--net=/proc/self/fd/3", "--", "ip", "link", "show", "dev", f.config.Interface)
	check.ExtraFiles = []*os.File{ns}
	if out, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("target interface: %w: %s", err, out)
	}
	flags := uint32(0)
	if f.config.FailOpenOnOverflow {
		flags = nfqueue.NfQaCfgFlagFailOpen
	}
	q, err := nfqueue.Open(&nfqueue.Config{NetNS: int(ns.Fd()), NfQueue: f.config.Queue, MaxQueueLen: f.config.MaxQueueLen, MaxPacketLen: 65535, Copymode: nfqueue.NfQnlCopyPacket, Flags: flags, WriteTimeout: f.config.Deadline})
	if err != nil {
		return fmt.Errorf("open NFQUEUE: %w", err)
	}
	queueCtx, cancel := context.WithCancel(ctx)
	defer func() { cancel(); result = errors.Join(result, q.Close()) }()
	jobs := f.worker(queueCtx)
	fatal := make(chan error, 1)
	fail := func(err error) {
		select {
		case fatal <- err:
		default:
		}
	}
	err = q.RegisterWithErrorFunc(queueCtx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			f.counts[8].Add(1)
			fail(errors.New("NFQUEUE message has no packet ID"))
			return 1
		}
		var raw []byte
		if a.Payload != nil {
			raw = *a.Payload
		}
		v := Deny
		select {
		case <-f.ready:
			v = f.decide(queueCtx, jobs, raw)
		default:
		}
		n := nfqueue.NfDrop
		if v == Allow {
			n = nfqueue.NfAccept
		}
		// One send attempt per packet: retrying a failed send can duplicate verdicts.
		if err := q.SetVerdict(*a.PacketID, n); err != nil {
			f.counts[8].Add(1)
			fail(fmt.Errorf("NFQUEUE verdict: %w", err))
			return 1
		}
		if n == nfqueue.NfAccept {
			f.counts[1].Add(1)
		} else {
			f.counts[2].Add(1)
		}
		return 0
	}, func(err error) int {
		if queueCtx.Err() != nil {
			return 1
		}
		f.counts[9].Add(1)
		// ENOBUFS means lost notifications, not permission to forget queued packets.
		// Stop and close the queue so the kernel resolves outstanding packets.
		fail(fmt.Errorf("NFQUEUE receive: %w", err))
		return 1
	})
	if err != nil {
		return fmt.Errorf("bind NFQUEUE: %w", err)
	}
	if err = f.install(ctx, ns, lock); err != nil {
		return err
	}
	defer func() {
		// A fatal listener error must preserve the configured absent-listener
		// policy. Only orderly context cancellation removes diversion hooks.
		if result != nil || f.config.OwnershipNonce != "" {
			return
		}
		cleanup, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		result = errors.Join(result, runNFT(cleanup, ns, "delete table inet "+tableName+"\n"))
	}()
	close(f.ready)
	select {
	case <-ctx.Done():
		return nil
	case err = <-fatal:
		return err
	}
}

func openNamespace(name string) (*os.File, error) {
	fd, err := unix.Open("/run/netns/"+name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		h, e := os.Stat(path)
		if e != nil {
			f.Close()
			return nil, e
		}
		if os.SameFile(info, h) {
			f.Close()
			return nil, errors.New("refusing current or PID 1 network namespace")
		}
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.NSFS_MAGIC {
		f.Close()
		return nil, errors.New("target must be a named network namespace bind mount")
	}
	return f, nil
}

func lockNamespace(ns *os.File, fence int) (*os.File, error) {
	// A namespace inode can be reused after a killed teardown. The kernel's
	// lifetime cookie keeps a future namespace out of that stale journal.
	cookie, err := unix.GetsockoptUint64(fence, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return nil, fmt.Errorf("namespace lifetime cookie unavailable: %w", err)
	}
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
	key := fmt.Sprintf("net-%x-%x-%x-inet-%s.lock", st.Dev, st.Ino, cookie, tableName)
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
		return nil, fmt.Errorf("namespace/table already owned or unsafe lock: %w", err)
	}
	return f, nil
}

func checkNode(fd int, kind, mode uint32) error {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return err
	}
	if s.Uid != 0 || s.Mode&unix.S_IFMT != kind || s.Mode&0022 != 0 || (mode != 0 && s.Mode&07777 != mode) || (kind == unix.S_IFREG && s.Nlink != 1) {
		return errors.New("lock path must be root owned, private, correct type and without hard links")
	}
	return nil
}

func runNFT(ctx context.Context, ns *os.File, script string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nsenter", "--net=/proc/self/fd/3", "--", "nft", "-f", "-")
	cmd.ExtraFiles = []*os.File{ns}
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scoped nft: %w: %s", err, stderr.String())
	}
	return nil
}

func (f *Firewall) rules() string {
	c := f.config
	var b strings.Builder
	// Exclusive create refuses stale/foreign tables; there is no flush or adoption.
	fmt.Fprintf(&b, "create table inet %s\nadd chain inet %s packets { type filter hook %s priority -10; policy accept; }\n", tableName, tableName, c.Hook)
	if c.OwnershipNonce != "" {
		b.Reset()
		fmt.Fprintf(&b, "create table inet %s { comment %s; }\nadd chain inet %s packets { type filter hook %s priority -10; policy accept; }\n", tableName, strconv.Quote("netcap-appliance:"+c.OwnershipNonce), tableName, c.Hook)
	}
	prefix := "add rule inet " + tableName + " packets "
	b.WriteString(prefix + "iifname \"lo\" return\n")
	for _, s := range c.ManagementDestinations {
		p, _ := netipPrefix(s)
		fmt.Fprintf(&b, "%s%s daddr %s return\n", prefix, p, s)
		fmt.Fprintf(&b, "%s%s saddr %s return\n", prefix, p, s)
	}
	queue := "queue num " + strconv.Itoa(int(c.Queue))
	if c.BypassWithoutListener {
		queue += " bypass"
	}
	for _, s := range c.ProtectedCIDRs {
		family, _ := netipPrefix(s)
		for _, address := range []string{"saddr", "daddr"} {
			fmt.Fprintf(&b, "%siifname %s %s %s %s %s\n", prefix, strconv.Quote(c.Interface), family, address, s, queue)
			if c.Hook == "forward" {
				fmt.Fprintf(&b, "%soifname %s %s %s %s %s\n", prefix, strconv.Quote(c.Interface), family, address, s, queue)
			}
		}
	}
	return b.String()
}
