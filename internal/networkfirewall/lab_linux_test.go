//go:build linux

package networkfirewall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Run only inside a disposable privileged Docker container:
// NETCAP_NETWORKFIREWALL_LAB=1 ./networkfirewall.test -test.v -test.run TestRoutedLab
func TestRoutedLab(t *testing.T) {
	if os.Getenv("NETCAP_NETWORKFIREWALL_LAB") != "1" {
		t.Skip("requires opt-in disposable privileged Docker lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("lab must run in disposable Docker container")
	}
	cmd := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	cmd("ip", "netns", "attach", "nfw-forbidden", "1")
	if ns, err := openNamespace("nfw-forbidden"); err == nil {
		ns.Close()
		t.Fatal("PID 1/current namespace accepted")
	}
	cmd("ip", "netns", "del", "nfw-forbidden")
	for _, n := range []string{"nfw-client", "nfw-gateway", "nfw-origin"} {
		cmd("ip", "netns", "add", n)
		t.Cleanup(func() {
			out, err := exec.Command("ip", "netns", "del", n).CombinedOutput()
			if err != nil {
				t.Errorf("cleanup %s: %v %s", n, err, out)
			}
		})
		cmd("ip", "-n", n, "link", "set", "lo", "up")
	}
	for _, pair := range [][4]string{{"c0", "g0", "nfw-client", "nfw-gateway"}, {"o0", "g1", "nfw-origin", "nfw-gateway"}} {
		cmd("ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1])
		cmd("ip", "link", "set", pair[0], "netns", pair[2])
		cmd("ip", "link", "set", pair[1], "netns", pair[3])
	}
	interfaces := [][5]string{{"nfw-client", "c0", "10.80.0.2/24", "fd80::2/64", "02:00:00:80:00:02"}, {"nfw-gateway", "g0", "10.80.0.1/24", "fd80::1/64", "02:00:00:80:00:01"}, {"nfw-gateway", "g1", "10.81.0.1/24", "fd81::1/64", "02:00:00:81:00:01"}, {"nfw-origin", "o0", "10.81.0.2/24", "fd81::2/64", "02:00:00:81:00:02"}}
	for _, a := range interfaces {
		cmd("ip", "-n", a[0], "link", "set", "dev", a[1], "address", a[4])
		// Only these disposable interfaces: also disable DAD for auto link-local addresses.
		cmd("ip", "netns", "exec", a[0], "sysctl", "-qw", "net.ipv6.conf."+a[1]+".accept_dad=0", "net.ipv6.conf."+a[1]+".dad_transmits=0")
		cmd("ip", "-n", a[0], "addr", "add", a[2], "dev", a[1])
		cmd("ip", "-n", a[0], "-6", "addr", "add", a[3], "dev", a[1], "nodad")
		cmd("ip", "-n", a[0], "link", "set", a[1], "up")
	}
	for _, a := range interfaces {
		deadline := time.Now().Add(3 * time.Second)
		for {
			data := cmd("ip", "-n", a[0], "-j", "addr", "show", "dev", a[1])
			if err := labInterfaceReady([]byte(data), strings.Split(a[2], "/")[0], strings.Split(a[3], "/")[0]); err == nil {
				break
			} else if time.Now().After(deadline) {
				t.Fatalf("interface %s/%s not ready: %v: %s", a[0], a[1], err, data)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// This qualifies routed verdicts, not ARP/NDP convergence. Pin every next-hop
	// neighbor in both directions so a cold first SYN cannot race resolution.
	for _, pair := range [][2]int{{0, 1}, {1, 0}, {2, 3}, {3, 2}} {
		local, peer := interfaces[pair[0]], interfaces[pair[1]]
		for _, cidr := range []string{peer[2], peer[3]} {
			cmd("ip", "-n", local[0], "neigh", "replace", strings.Split(cidr, "/")[0], "lladdr", peer[4], "nud", "permanent", "dev", local[1])
		}
	}
	for _, r := range [][3]string{{"nfw-client", "10.80.0.1", "fd80::1"}, {"nfw-origin", "10.81.0.1", "fd81::1"}} {
		cmd("ip", "-n", r[0], "route", "add", "default", "via", r[1])
		cmd("ip", "-n", r[0], "-6", "route", "add", "default", "via", r[2])
	}
	cmd("ip", "netns", "exec", "nfw-gateway", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
	// An unrelated table must survive startup, failures and teardown byte-for-byte.
	cmd("ip", "netns", "exec", "nfw-gateway", "nft", "add", "table", "inet", "unrelated")
	before := cmd("ip", "netns", "exec", "nfw-gateway", "nft", "list", "table", "inet", "unrelated")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startServer := func(ns, addr, network string) {
		t.Helper()
		ready, signal, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer ready.Close()
		c := exec.Command("ip", "netns", "exec", ns, exe, "-test.run=^TestLabHelper$")
		c.ExtraFiles = []*os.File{signal}
		role := "server"
		if strings.HasSuffix(addr, ":8443") {
			role = "hello-server"
		}
		c.Env = append(os.Environ(), "NFW_HELPER="+role, "NFW_ADDRESS="+addr, "NFW_NETWORK="+network, "NFW_READY_FD=3")
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			signal.Close()
			t.Fatal(err)
		}
		signal.Close()
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		if err := labWaitReady(ready); err != nil {
			t.Fatalf("server %s %s %s: %v", ns, network, addr, err)
		}
	}
	for _, port := range []int{8080, 8081} {
		for _, network := range []string{"tcp", "udp"} {
			startServer("nfw-origin", fmt.Sprintf("[::]:%d", port), network)
			startServer("nfw-gateway", fmt.Sprintf("[::]:%d", port), network)
		}
	}
	startServer("nfw-origin", "[::]:8443", "tcp")
	runProbe := func(addr, network string) ([]byte, error) {
		c := exec.Command("ip", "netns", "exec", "nfw-client", exe, "-test.run=^TestLabHelper$")
		role := "client"
		if network == "fragment" {
			role = "fragment-client"
			network = "udp"
		}
		if network == "hello" {
			role = "hello-client"
			network = "tcp"
		}
		c.Env = append(os.Environ(), "NFW_HELPER="+role, "NFW_ADDRESS="+addr, "NFW_NETWORK="+network)
		return c.CombinedOutput()
	}
	probeNet := func(addr, network string, want bool) {
		t.Helper()
		out, err := runProbe(addr, network)
		if (err == nil) != want {
			t.Fatalf("probe %s success=%v want=%v: %s", addr, err == nil, want, out)
		}
	}
	probe := func(addr string, want bool) { t.Helper(); probeNet(addr, "tcp", want) }
	// IPv6 is deliberately the first real dataplane probe in each cold fixture.
	for _, addr := range []string{"[fd81::2]:8080", "10.81.0.2:8080", "[fd81::2]:8081", "10.81.0.2:8081"} {
		probe(addr, true)
	}
	t.Log("cold IPv6-first baseline passed with unchanged 700ms probes")
	// Readiness must not disguise a missing route or listener as successful traffic.
	cmd("ip", "-n", "nfw-client", "-6", "route", "del", "default")
	if out, err := runProbe("[fd81::2]:8080", "tcp"); err == nil || !strings.Contains(string(out), "network is unreachable") {
		t.Fatalf("broken-route negative control: %v: %s", err, out)
	}
	cmd("ip", "-n", "nfw-client", "-6", "route", "add", "default", "via", "fd80::1")
	probe("[fd81::2]:8080", true)
	if out, err := runProbe("[fd81::2]:8099", "tcp"); err == nil || !strings.Contains(string(out), "connection refused") {
		t.Fatalf("absent-listener negative control: %v: %s", err, out)
	}
	t.Log("baseline negative controls rejected broken IPv6 route and absent listener")
	start := func(c Config, e Evaluator) (*Firewall, func()) {
		t.Helper()
		f, err := New(c, e)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- f.Run(ctx) }()
		select {
		case <-f.Ready():
		case err := <-done:
			cancel()
			t.Fatalf("start: %v", err)
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("start timeout")
		}
		stop := sync.OnceFunc(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown timeout")
			}
		})
		t.Cleanup(stop)
		return f, stop
	}
	policy := evaluatorFunc(func(p PacketEvent) (Decision, error) {
		if p.DstPort == 8081 {
			return Decision{Deny}, nil
		}
		return Decision{Allow}, nil
	})
	for _, hook := range []string{"forward", "input"} {
		t.Run(hook, func(t *testing.T) {
			c := testConfig()
			c.Interface = "g0"
			c.Hook = hook
			c.Deadline = 100 * time.Millisecond
			f, stop := start(c, policy)
			host4, host6 := "10.81.0.2", "fd81::2"
			if hook == "input" {
				host4 = "10.80.0.1"
				host6 = "fd80::1"
			}
			probe(net.JoinHostPort(host4, "8080"), true)
			probe(net.JoinHostPort(host6, "8080"), true)
			probe(net.JoinHostPort(host4, "8081"), false)
			probe(net.JoinHostPort(host6, "8081"), false)
			probeNet(net.JoinHostPort(host4, "8080"), "udp", true)
			probeNet(net.JoinHostPort(host6, "8080"), "udp", true)
			probeNet(net.JoinHostPort(host4, "8081"), "udp", false)
			probeNet(net.JoinHostPort(host6, "8081"), "udp", false)
			// Same namespace/table cannot be claimed by a second controller.
			other, _ := New(c, policy)
			if err := other.Run(context.Background()); err == nil {
				t.Fatal("second owner accepted")
			}
			stop()
			if s := f.Stats(); s.Accepted == 0 || s.Dropped == 0 || s.VerdictErrors != 0 || s.ReceiveErrors != 0 {
				t.Fatal(s)
			} else {
				t.Logf("real %s counters: %+v", hook, s)
			}
			probe(net.JoinHostPort(host4, "8081"), true)
		})
	}
	c := testConfig()
	c.Interface = "g0"
	c.ManagementDestinations = []string{"10.81.0.2/32", "fd81::2/128"}
	_, stop := start(c, evaluatorFunc(func(PacketEvent) (Decision, error) { return Decision{Deny}, nil }))
	probe("10.81.0.2:8081", true)
	probe("[fd81::2]:8081", true)
	stop()
	// Listener absence has explicit fail-closed and bypass variants.
	ns, err := openNamespace(c.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	for _, bypass := range []bool{false, true} {
		c.BypassWithoutListener = bypass
		c.ManagementDestinations = nil
		f, _ := New(c, policy)
		if err := runNFT(context.Background(), ns, f.rules()); err != nil {
			t.Fatal(err)
		}
		probe("10.81.0.2:8080", bypass)
		probe("[fd81::2]:8080", bypass)
		if err := runNFT(context.Background(), ns, "delete table inet "+tableName+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	// Evaluator failure is a real packet drop, not just an error counter.
	f, stop := start(c, evaluatorFunc(func(PacketEvent) (Decision, error) { return Decision{}, fmt.Errorf("policy unavailable") }))
	probe("10.81.0.2:8080", false)
	probe("[fd81::2]:8080", false)
	stop()
	if f.Stats().EvaluationErrors == 0 {
		t.Fatal(f.Stats())
	}
	// Deadline and saturation under actual traffic must resolve through the
	// configured failure verdict without accumulating evaluator goroutines.
	blocked := make(chan struct{})
	c.FailureVerdict = Deny
	f, stop = start(c, evaluatorFunc(func(PacketEvent) (Decision, error) { <-blocked; return Decision{Allow}, nil }))
	probeNet("10.81.0.2:8080", "udp", false)
	probeNet("[fd81::2]:8080", "udp", false)
	stop()
	close(blocked)
	if s := f.Stats(); s.Deadlines == 0 || s.Overloads == 0 {
		t.Fatal(s)
	}
	// Monitor mode and explicit fail-open both forward real denied traffic.
	for _, mode := range []string{"monitor", "failure-open"} {
		c.FailureVerdict = Allow
		c.FailOpenOnOverflow = mode == "failure-open"
		f, stop = start(c, evaluatorFunc(func(PacketEvent) (Decision, error) {
			if mode == "monitor" {
				return Decision{WouldDeny}, nil
			}
			return Decision{}, fmt.Errorf("unavailable")
		}))
		probe("10.81.0.2:8081", true)
		probe("[fd81::2]:8081", true)
		stop()
		if f.Stats().Dropped != 0 || f.Stats().Accepted == 0 {
			t.Fatal(f.Stats())
		}
	}
	c.InspectTLS = true
	f, stop = start(c, evaluatorFunc(func(e PacketEvent) (Decision, error) {
		if e.TLS != nil && e.TLS.ServerName == "example.test" {
			return Decision{Deny}, nil
		}
		return Decision{Allow}, nil
	}))
	probeNet("10.81.0.2:8443", "hello", false)
	probeNet("[fd81::2]:8443", "hello", false)
	stop()
	if f.Stats().Dropped < 2 {
		t.Fatal("visible split ClientHello did not cause a packet drop", f.Stats())
	}
	probeNet("10.81.0.2:8443", "hello", true)
	c.InspectTLS = false
	c.FailureVerdict = Deny
	f, stop = start(c, evaluatorFunc(func(PacketEvent) (Decision, error) { return Decision{Allow}, nil }))
	probeNet("10.81.0.2:8080", "fragment", false)
	stop()
	if f.Stats().ParseErrors == 0 {
		t.Fatal("fragment did not take explicit failure verdict", f.Stats())
	}
	probeNet("10.81.0.2:8080", "fragment", true)
	after := cmd("ip", "netns", "exec", "nfw-gateway", "nft", "list", "table", "inet", "unrelated")
	if before != after {
		t.Fatalf("unrelated table changed: %q -> %q", before, after)
	}
	if tables := cmd("ip", "netns", "exec", "nfw-gateway", "nft", "list", "tables"); strings.Contains(tables, tableName) {
		t.Fatal("owned table leaked")
	}
	cmd("ip", "netns", "exec", "nfw-gateway", "nft", "add", "table", "inet", tableName)
	foreign := cmd("ip", "netns", "exec", "nfw-gateway", "nft", "list", "table", "inet", tableName)
	other, _ := New(c, policy)
	if err := other.Run(context.Background()); err == nil {
		t.Fatal("existing foreign/stale table accepted")
	}
	if got := cmd("ip", "netns", "exec", "nfw-gateway", "nft", "list", "table", "inet", tableName); got != foreign {
		t.Fatal("existing table changed")
	}
	cmd("ip", "netns", "exec", "nfw-gateway", "nft", "delete", "table", "inet", tableName)
}

func TestLabHelper(t *testing.T) {
	role := os.Getenv("NFW_HELPER")
	if role == "" {
		t.Skip("subprocess helper")
	}
	addr := os.Getenv("NFW_ADDRESS")
	network := os.Getenv("NFW_NETWORK")
	if network == "" {
		network = "tcp"
	}
	if role == "fragment-client" {
		receiver, err := net.ListenPacket("udp4", "10.80.0.2:33445")
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		data := make([]byte, 24)
		binary.BigEndian.PutUint16(data[:2], 33445)
		binary.BigEndian.PutUint16(data[2:4], 8080)
		binary.BigEndian.PutUint16(data[4:6], 24)
		copy(data[8:], "fragment-payload")
		for i, chunk := range [][]byte{data[:16], data[16:]} {
			b := make([]byte, 20+len(chunk))
			b[0] = 0x45
			binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
			binary.BigEndian.PutUint16(b[4:6], 32123)
			b[8] = 64
			b[9] = 17
			if i == 0 {
				b[6] = 0x20
			} else {
				b[7] = 2
			}
			copy(b[12:16], []byte{10, 80, 0, 2})
			copy(b[16:20], []byte{10, 81, 0, 2})
			copy(b[20:], chunk)
			if err := unix.Sendto(fd, b, 0, &unix.SockaddrInet4{Addr: [4]byte{10, 81, 0, 2}}); err != nil {
				t.Fatal(err)
			}
		}
		_ = receiver.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		b := make([]byte, 64)
		n, _, err := receiver.ReadFrom(b)
		if err != nil || n != 16 {
			t.Fatalf("fragment origin response: %d %v", n, err)
		}
		return
	}
	if role == "server" || role == "hello-server" {
		if network == "udp" {
			c, err := net.ListenPacket("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			labSignalReady(t)
			b := make([]byte, 1024)
			for {
				n, peer, err := c.ReadFrom(b)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.WriteTo(b[:n], peer); err != nil {
					t.Fatal(err)
				}
			}
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		labSignalReady(t)
		for {
			c, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if role == "hello-server" {
					b := make([]byte, len(helloFixture()))
					if _, err := io.ReadFull(c, b); err == nil {
						_, _ = c.Write([]byte("ping"))
					}
					return
				}
				_, _ = io.CopyN(c, c, 4)
			}()
		}
	}
	c, err := net.DialTimeout(network, addr, 700*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
	payload := []byte("ping")
	if role == "hello-client" {
		payload = helloFixture()
		if _, err = c.Write(payload[:9]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		payload = payload[9:]
	}
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("origin response %q: %v", b, err)
	}
}

func labInterfaceReady(data []byte, ipv4, ipv6 string) error {
	var links []struct {
		Flags     []string
		Addresses []struct {
			Local     string
			Flags     []string
			Tentative bool
			DADFailed bool `json:"dadfailed"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return err
	}
	if len(links) != 1 {
		return fmt.Errorf("expected one fixture interface, got %d", len(links))
	}
	flags := "," + strings.Join(links[0].Flags, ",") + ","
	if !strings.Contains(flags, ",UP,") || !strings.Contains(flags, ",LOWER_UP,") {
		return fmt.Errorf("link not up: %v", links[0].Flags)
	}
	found4, found6 := false, false
	for _, a := range links[0].Addresses {
		if a.Tentative || a.DADFailed {
			return fmt.Errorf("address %s has not completed DAD", a.Local)
		}
		for _, flag := range a.Flags {
			if flag == "tentative" || flag == "dadfailed" {
				return fmt.Errorf("address %s is %s", a.Local, flag)
			}
		}
		found4 = found4 || a.Local == ipv4
		found6 = found6 || a.Local == ipv6
	}
	if !found4 || !found6 {
		return fmt.Errorf("expected ready addresses %s and %s", ipv4, ipv6)
	}
	return nil
}

func labWaitReady(ready *os.File) error {
	if err := ready.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	var signal [1]byte
	if _, err := io.ReadFull(ready, signal[:]); err != nil {
		return fmt.Errorf("listener readiness signal: %w", err)
	}
	if signal[0] != 1 {
		return fmt.Errorf("invalid listener readiness signal %d", signal[0])
	}
	return nil
}

func labSignalReady(t *testing.T) {
	t.Helper()
	value := os.Getenv("NFW_READY_FD")
	if value == "" {
		// The packaged CLI fixture also uses this helper without a ready pipe.
		return
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 {
		t.Fatal("server readiness descriptor required")
	}
	f := os.NewFile(uintptr(fd), "listener-ready")
	if _, err = f.Write([]byte{1}); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLabReadinessRejectsIncompleteFixture(t *testing.T) {
	valid := `[{"flags":["UP","LOWER_UP"],"addr_info":[{"local":"10.80.0.2"},{"local":"fd80::2"}]}]`
	if err := labInterfaceReady([]byte(valid), "10.80.0.2", "fd80::2"); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`[]`, strings.Replace(valid, `"LOWER_UP"`, `"NO-CARRIER"`, 1), strings.Replace(valid, `"fd80::2"`, `"fd80::3"`, 1), strings.Replace(valid, `"local":"fd80::2"`, `"local":"fd80::2","tentative":true`, 1), strings.Replace(valid, `"local":"fd80::2"`, `"local":"fd80::2","flags":["dadfailed"]`, 1)} {
		if err := labInterfaceReady([]byte(invalid), "10.80.0.2", "fd80::2"); err == nil {
			t.Fatalf("incomplete interface accepted: %s", invalid)
		}
	}
	for _, signal := range [][]byte{nil, {0}, {1}} {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = write.Write(signal); err != nil {
			t.Fatal(err)
		}
		write.Close()
		err = labWaitReady(read)
		read.Close()
		want := len(signal) == 1 && signal[0] == 1
		if (err == nil) != want {
			t.Fatalf("listener readiness %v: %v", signal, err)
		}
	}
}
