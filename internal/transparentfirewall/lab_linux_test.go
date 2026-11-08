//go:build linux

package transparentfirewall

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Cross-compile this package's test binary for the Docker daemon architecture,
// mount it at /transparentfirewall.test in Dockerfile.lab, then run privileged
// with --network none. No namespace or route outside that container is changed.
func TestTransparentLab(t *testing.T) {
	transparentLab(t, false)
}

func TestTransparentShippingCLI(t *testing.T) {
	transparentLab(t, true)
}

func transparentLab(t *testing.T, shipping bool) {
	if os.Getenv("NETCAP_TRANSPARENTFIREWALL_LAB") != "1" {
		t.Skip("requires opt-in disposable privileged Docker lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable Docker container required")
	}
	command := func(args ...string) string {
		t.Helper()
		b, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, b)
		}
		return string(b)
	}
	command("ip", "netns", "attach", "tfw-forbidden", "1")
	if ns, err := openNamespace("tfw-forbidden"); err == nil {
		ns.Close()
		t.Fatal("PID 1/current namespace accepted")
	}
	command("ip", "netns", "del", "tfw-forbidden")
	defaultRules := command("nft", "-j", "list", "ruleset")
	defaultLinks := command("ip", "-j", "link", "show")
	for _, n := range []string{"tfw-client", "tfw-gateway", "tfw-origin"} {
		command("ip", "netns", "add", n)
		t.Cleanup(func() {
			b, err := exec.Command("ip", "netns", "del", n).CombinedOutput()
			if err != nil {
				t.Errorf("cleanup: %s: %v %s", n, err, b)
			}
		})
		command("ip", "-n", n, "link", "set", "lo", "up")
	}
	for _, p := range [][4]string{{"c0", "g0", "tfw-client", "tfw-gateway"}, {"o0", "g1", "tfw-origin", "tfw-gateway"}} {
		command("ip", "link", "add", p[0], "type", "veth", "peer", "name", p[1])
		command("ip", "link", "set", p[0], "netns", p[2])
		command("ip", "link", "set", p[1], "netns", p[3])
	}
	for _, a := range [][4]string{{"tfw-client", "c0", "10.90.0.2/24", "fd90::2/64"}, {"tfw-gateway", "g0", "10.90.0.1/24", "fd90::1/64"}, {"tfw-gateway", "g1", "10.91.0.1/24", "fd91::1/64"}, {"tfw-origin", "o0", "10.91.0.2/24", "fd91::2/64"}} {
		command("ip", "-n", a[0], "addr", "add", a[2], "dev", a[1])
		command("ip", "-n", a[0], "-6", "addr", "add", a[3], "dev", a[1], "nodad")
		command("ip", "-n", a[0], "link", "set", a[1], "up")
	}
	for _, r := range [][3]string{{"tfw-client", "10.90.0.1", "fd90::1"}, {"tfw-origin", "10.91.0.1", "fd91::1"}} {
		command("ip", "-n", r[0], "route", "add", "default", "via", r[1])
		command("ip", "-n", r[0], "-6", "route", "add", "default", "via", r[2])
	}
	command("ip", "netns", "exec", "tfw-gateway", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
	command("ip", "-n", "tfw-origin", "addr", "add", "10.91.0.3/24", "dev", "o0")
	command("ip", "-n", "tfw-origin", "-6", "addr", "add", "fd91::3/64", "dev", "o0", "nodad")
	command("ip", "-n", "tfw-client", "addr", "add", "10.90.0.3/24", "dev", "c0")
	command("ip", "-n", "tfw-client", "-6", "addr", "add", "fd90::3/64", "dev", "c0", "nodad")
	command("ip", "netns", "exec", "tfw-gateway", "nft", "add", "table", "inet", "unrelated")
	unrelated := command("ip", "netns", "exec", "tfw-gateway", "nft", "list", "table", "inet", "unrelated")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(ns, role, protocol, address, upstream, log string) *exec.Cmd {
		t.Helper()
		c := exec.Command("ip", "netns", "exec", ns, exe, "-test.run=^TestPlacementHelper$")
		if role == "gateway" {
			binary := os.Getenv("TFW_GATEWAY_BINARY")
			if binary == "" {
				t.Fatal("TFW_GATEWAY_BINARY must name the real netcap-firewall CLI inside the disposable container")
			}
			// An allowed reply also proves the gateway retained the original
			// client address: a namespace-local or origin address fails this rule.
			bundle := map[string]any{"version": "1", "id": "transparent-lab", "mode": "enforce", "default": "allow", "rules": []map[string]string{
				{"id": "client-identity", "action": "deny", "expression": `ClientIP != "10.90.0.2" && ClientIP != "fd90::2"`},
				{"id": "deny-write", "action": "deny", "expression": `Method == "FLUSHALL" || (Protocol == "dnp3" && Attributes["dnp3.function"] == "2")`},
			}}
			data, err := json.Marshal(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(log, data, 0600); err != nil {
				t.Fatal(err)
			}
			c = exec.Command("ip", "netns", "exec", ns, binary, "gateway", "--protocol", protocol, "--listen", address, "--upstream", upstream, "--policy", log, "--allow-client", "10.90.0.2/32", "--allow-client", "fd90::2/128", "--io-timeout", "1s", "--idle-timeout", "1s")
		}
		c.Env = append(os.Environ(), "TFW_ROLE="+role, "TFW_PROTOCOL="+protocol, "TFW_ADDRESS="+address, "TFW_UPSTREAM="+upstream, "TFW_LOG="+log)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		return c
	}
	probeClient := func(t *testing.T, protocol, host string, port int, forbidden, want bool) {
		t.Helper()
		c := exec.Command("ip", "netns", "exec", "tfw-client", exe, "-test.run=^TestPlacementHelper$")
		c.Env = append(os.Environ(), "TFW_ROLE=client", "TFW_PROTOCOL="+protocol, "TFW_ADDRESS="+net.JoinHostPort(host, strconv.Itoa(port)), fmt.Sprintf("TFW_FORBIDDEN=%t", forbidden))
		b, err := c.CombinedOutput()
		if (err == nil) != want {
			t.Fatalf("%s %s:%d forbidden=%v success=%v want=%v: %s", protocol, host, port, forbidden, err == nil, want, b)
		}
	}
	probeUDP := func(t *testing.T, host string, port int) {
		t.Helper()
		c := exec.Command("ip", "netns", "exec", "tfw-client", exe, "-test.run=^TestPlacementHelper$")
		c.Env = append(os.Environ(), "TFW_ROLE=udp-client", "TFW_ADDRESS="+net.JoinHostPort(host, strconv.Itoa(port)))
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("unrelated UDP changed: %v: %s", err, out)
		}
	}
	count := func(path, needle string) int {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return strings.Count(string(b), needle)
	}
	for _, p := range []struct {
		protocol      string
		port, gateway int
	}{{"redis", 6379, 16379}, {"dnp3", 20000, 21000}} {
		log := t.TempDir() + "/" + p.protocol
		start("tfw-origin", "origin", p.protocol, fmt.Sprintf("[::]:%d", p.port), "", log)
		// Wildcard UDP replies can select the other local alias as their source.
		start("tfw-origin", "udp-origin", p.protocol, fmt.Sprintf("10.91.0.2:%d", p.port), "", log)
		start("tfw-origin", "udp-origin", p.protocol, fmt.Sprintf("[fd91::2]:%d", p.port), "", log)
		// An unrelated service port must continue to reach the origin directly.
		start("tfw-origin", "origin", p.protocol, fmt.Sprintf("[::]:%d", p.port+1), "", log)
		time.Sleep(2 * time.Second)
		for _, family := range []struct{ name, service, other, gateway, originPeer string }{{"ipv4", "10.91.0.2", "10.91.0.3", "10.90.0.1", "10.91.0.1"}, {"ipv6", "fd91::2", "fd91::3", "fd90::1", "fd91::1"}} {
			t.Run(p.protocol+"/"+family.name, func(t *testing.T) {
				c := testConfig()
				c.Protocol = p.protocol
				c.OriginalService = family.service
				c.OriginalPort = p.port
				c.GatewayPort = p.gateway
				// Baseline proves forbidden fixture messages are accepted by the origin.
				probeClient(t, p.protocol, family.service, p.port, true, true)
				fdsBefore, _ := os.ReadDir("/proc/self/fd")
				if shipping {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					refused := exec.CommandContext(ctx, os.Getenv("TFW_GATEWAY_BINARY"), redirectArguments(c)...)
					out, err := refused.CombinedOutput()
					cancel()
					if err == nil || !strings.Contains(string(out), "gateway listener not ready") {
						t.Fatalf("shipping redirect missing-listener refusal: %v: %s", err, out)
					}
					if strings.Contains(command("ip", "netns", "exec", c.NetworkNamespace, "nft", "list", "tables"), tableName) {
						t.Fatal("failed CLI activation leaked table")
					}
				} else {
					for attempt := 0; attempt < 10; attempt++ {
						if cleanup, err := Install(context.Background(), c); err == nil {
							cleanup()
							t.Fatal("installed without an existing local gateway listener")
						}
					}
				}
				fdsAfter, _ := os.ReadDir("/proc/self/fd")
				if len(fdsBefore) != len(fdsAfter) {
					t.Fatalf("failed activation leaked descriptors: %d -> %d", len(fdsBefore), len(fdsAfter))
				}
				gatewayLog := t.TempDir() + "/gateway"
				child := start("tfw-gateway", "gateway", p.protocol, net.JoinHostPort(family.gateway, strconv.Itoa(p.gateway)), net.JoinHostPort(family.service, strconv.Itoa(p.port)), gatewayLog)
				ns, err := openNamespace(c.NetworkNamespace)
				if err != nil {
					t.Fatal(err)
				}
				ready := false
				for i := 0; i < 100; i++ {
					if probe(context.Background(), ns, netip.MustParseAddr(family.gateway), p.gateway) == nil {
						ready = true
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				ns.Close()
				if !ready {
					t.Fatal("gateway startup failed")
				}
				if shipping {
					invalid := c
					invalid.TLSMode = "passthrough"
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					out, err := exec.CommandContext(ctx, os.Getenv("TFW_GATEWAY_BINARY"), redirectArguments(invalid)...).CombinedOutput()
					cancel()
					if err == nil || !strings.Contains(string(out), "opaque TLS is not inspected") {
						t.Fatalf("shipping redirect opaque-TLS refusal: %v: %s", err, out)
					}
					process := startRedirectCLI(t, c)
					forbidden := "redis:FLUSHALL"
					if p.protocol == "dnp3" {
						forbidden = "dnp3:2"
					}
					before := count(log, forbidden)
					probeClient(t, p.protocol, family.service, p.port, false, true)
					probeClient(t, p.protocol, family.service, p.port, true, false)
					if count(log, forbidden) != before {
						t.Fatal("forbidden CLI-routed command reached origin")
					}
					source := "10.90.0.3"
					if family.name == "ipv6" {
						source = "fd90::3"
					}
					blocked := exec.Command("ip", "netns", "exec", "tfw-client", exe, "-test.run=^TestPlacementHelper$")
					blocked.Env = append(os.Environ(), "TFW_ROLE=client", "TFW_PROTOCOL="+p.protocol, "TFW_ADDRESS="+net.JoinHostPort(family.service, strconv.Itoa(p.port)), "TFW_SOURCE="+source)
					originBefore, _ := os.ReadFile(log)
					if out, err := blocked.CombinedOutput(); err == nil {
						t.Fatalf("gateway source ACL allowed alternate peer: %s", out)
					}
					originAfter, _ := os.ReadFile(log)
					if string(originBefore) != string(originAfter) {
						t.Fatal("ACL-rejected peer reached origin")
					}
					if count(log, "peer="+family.originPeer) == 0 {
						t.Fatal("shipping gateway upstream was not namespace-local")
					}
					probeClient(t, p.protocol, family.other, p.port, true, true)
					probeClient(t, p.protocol, family.service, p.port+1, true, true)
					probeUDP(t, family.service, p.port)
					if err := process.stop(); err != nil {
						t.Fatalf("shipping redirect SIGTERM: %v", err)
					}
					if strings.Contains(command("ip", "netns", "exec", c.NetworkNamespace, "nft", "list", "tables"), tableName) {
						t.Fatal("SIGTERM left redirect table")
					}
					if got := command("ip", "netns", "exec", c.NetworkNamespace, "nft", "list", "table", "inet", "unrelated"); got != unrelated {
						t.Fatal("SIGTERM changed unrelated table")
					}
					probeClient(t, p.protocol, family.service, p.port, true, true)
					if count(log, forbidden) <= before {
						t.Fatal("SIGTERM did not restore direct origin traffic")
					}
					peer := "10.90.0.2/32"
					if family.name == "ipv6" {
						peer = "fd90::2/128"
					}
					c.ManagementPeers = []string{peer}
					management := startRedirectCLI(t, c)
					probeClient(t, p.protocol, family.service, p.port, true, true)
					if err := management.stop(); err != nil {
						t.Fatal("management redirect SIGTERM", err)
					}
					if strings.Contains(command("ip", "netns", "exec", c.NetworkNamespace, "nft", "list", "tables"), tableName) {
						t.Fatal("management SIGTERM left redirect table")
					}
					if err := child.Process.Kill(); err != nil {
						t.Fatal(err)
					}
					return
				}
				cleanup, err := Install(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				firstCleanup := cleanup
				t.Cleanup(func() {
					if err := firstCleanup(); err != nil {
						t.Error(err)
					}
				})
				if duplicate, err := Install(context.Background(), c); err == nil {
					duplicate()
					t.Fatal("duplicate table owner accepted")
				}
				forbidden := "redis:FLUSHALL"
				if p.protocol == "dnp3" {
					forbidden = "dnp3:2"
				}
				before := count(log, forbidden)
				probeClient(t, p.protocol, family.service, p.port, false, true)
				probeClient(t, p.protocol, family.service, p.port, true, false)
				if got := count(log, forbidden); got != before {
					t.Fatalf("forbidden command reached origin: %d -> %d", before, got)
				}
				if count(log, "peer="+family.originPeer) == 0 {
					t.Fatal("upstream socket was not in gateway namespace")
				}
				probeClient(t, p.protocol, family.service, p.port+1, true, true)
				probeClient(t, p.protocol, family.other, p.port, true, true)
				probeUDP(t, family.service, p.port)
				if err := cleanup(); err != nil {
					t.Fatal(err)
				}
				// Management source and destination exemptions each keep the
				// entire connection direct, even for a command the gateway denies.
				clientPeer := "10.90.0.2/32"
				servicePeer := family.service + "/32"
				if family.name == "ipv6" {
					clientPeer = "fd90::2/128"
					servicePeer = family.service + "/128"
				}
				for _, peer := range []string{clientPeer, servicePeer} {
					c.ManagementPeers = []string{peer}
					var err error
					cleanup, err = Install(context.Background(), c)
					if err != nil {
						t.Fatal(err)
					}
					probeClient(t, p.protocol, family.service, p.port, true, true)
					if err = cleanup(); err != nil {
						t.Fatal(err)
					}
				}
				c.ManagementPeers = nil
				// A stale/foreign table is never adopted, changed, or removed.
				command("ip", "netns", "exec", "tfw-gateway", "nft", "add", "table", "inet", tableName)
				foreign := command("ip", "netns", "exec", "tfw-gateway", "nft", "list", "table", "inet", tableName)
				if accidental, err := Install(context.Background(), c); err == nil {
					accidental()
					t.Fatal("foreign table accepted")
				}
				if got := command("ip", "netns", "exec", "tfw-gateway", "nft", "list", "table", "inet", tableName); got != foreign {
					t.Fatal("foreign table changed")
				}
				command("ip", "netns", "exec", "tfw-gateway", "nft", "delete", "table", "inet", tableName)
				// Cleanup must not delete an externally replaced table, and must
				// retain ownership until a later successful cleanup retry.
				driftCleanup, err := Install(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				command("ip", "netns", "exec", "tfw-gateway", "nft", "delete", "table", "inet", tableName)
				command("ip", "netns", "exec", "tfw-gateway", "nft", "add", "table", "inet", tableName)
				if err := driftCleanup(); !errors.Is(err, errOwnerChanged) {
					t.Fatalf("replacement table cleanup: %v", err)
				}
				if accidental, err := Install(context.Background(), c); err == nil {
					accidental()
					t.Fatal("cleanup failure released singleton ownership")
				}
				command("ip", "netns", "exec", "tfw-gateway", "nft", "list", "table", "inet", tableName)
				command("ip", "netns", "exec", "tfw-gateway", "nft", "delete", "table", "inet", tableName)
				if err := driftCleanup(); err != nil {
					t.Fatal("cleanup retry failed", err)
				}
				c.OriginalService = family.service + "/31"
				if family.name == "ipv6" {
					c.OriginalService = family.service + "/127"
				}
				cleanup, err = Install(context.Background(), c)
				if err != nil {
					t.Fatal(err)
				}
				finalCleanup := cleanup
				t.Cleanup(func() {
					if err := finalCleanup(); err != nil {
						t.Error(err)
					}
				})
				probeClient(t, p.protocol, family.other, p.port, false, true)
				probeClient(t, p.protocol, family.other, p.port, true, false)
				// Kill the listener: new intercepted sessions must fail, never fall
				// through to the original service while the placement remains active.
				if err := child.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				time.Sleep(25 * time.Millisecond)
				before = count(log, forbidden)
				probeClient(t, p.protocol, family.service, p.port, true, false)
				if count(log, forbidden) != before {
					t.Fatal("dead gateway bypassed to origin")
				}
				if err := cleanup(); err != nil {
					t.Fatal(err)
				}
				if err := cleanup(); err != nil {
					t.Fatal("cleanup is not idempotent", err)
				}
				probeClient(t, p.protocol, family.service, p.port, true, true)
			})
		}
	}
	if got := command("ip", "netns", "exec", "tfw-gateway", "nft", "list", "table", "inet", "unrelated"); got != unrelated {
		t.Fatal("unrelated table changed")
	}
	if tables := command("ip", "netns", "exec", "tfw-gateway", "nft", "list", "tables"); strings.Contains(tables, tableName) {
		t.Fatal("placement table leaked")
	}
	if got := command("nft", "-j", "list", "ruleset"); got != defaultRules {
		t.Fatal("container default namespace ruleset changed")
	}
	if got := command("ip", "-j", "link", "show"); got != defaultLinks {
		t.Fatal("container default namespace interfaces changed")
	}
}

func redirectArguments(c Config) []string {
	args := []string{"redirect", "--namespace", c.NetworkNamespace, "--interface", c.IngressInterface, "--service-cidr", c.OriginalService, "--service-port", strconv.Itoa(c.OriginalPort), "--gateway-port", strconv.Itoa(c.GatewayPort), "--protocol", c.Protocol, "--tls-mode", c.TLSMode}
	for _, peer := range c.ManagementPeers {
		args = append(args, "--management-peer", peer)
	}
	return args
}

type redirectProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error
	once    sync.Once
	stopErr error
}

func (p *redirectProcess) stop() error {
	p.once.Do(func() {
		select {
		case <-p.done:
			p.stopErr = p.err
			return
		default:
		}
		if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			p.stopErr = err
		}
		select {
		case <-p.done:
			p.stopErr = errors.Join(p.stopErr, p.err)
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
			p.stopErr = errors.Join(p.stopErr, errors.New("redirect did not exit after SIGTERM"), p.err)
		}
	})
	return p.stopErr
}

func startRedirectCLI(t *testing.T, c Config) *redirectProcess {
	t.Helper()
	logPath := t.TempDir() + "/redirect.log"
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cmd := exec.Command(os.Getenv("TFW_GATEWAY_BINARY"), redirectArguments(c)...)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &redirectProcess{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		if err := p.stop(); err != nil {
			t.Error(err)
		}
	})
	ns, err := openNamespace(c.NetworkNamespace)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-p.done:
			b, _ := os.ReadFile(logPath)
			t.Fatalf("redirect exited before activation: %v: %s", p.err, b)
		case <-deadline:
			b, _ := os.ReadFile(logPath)
			t.Fatalf("redirect activation timed out: %s", b)
		default:
		}
		out, err := run(context.Background(), ns, "nft", "", "list", "tables")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "table inet "+tableName) {
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPlacementHelper(t *testing.T) {
	role := os.Getenv("TFW_ROLE")
	if role == "" {
		t.Skip("subprocess fixture")
	}
	protocol, address, log := os.Getenv("TFW_PROTOCOL"), os.Getenv("TFW_ADDRESS"), os.Getenv("TFW_LOG")
	if role == "udp-origin" {
		c, err := net.ListenPacket("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		b := make([]byte, 64)
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
	if role == "udp-client" {
		c, err := net.DialTimeout("udp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err = c.Write([]byte("datagram")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 8)
		if _, err = io.ReadFull(c, b); err != nil || string(b) != "datagram" {
			t.Fatalf("UDP response %q: %v", b, err)
		}
		return
	}
	if role == "origin" {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		for {
			c, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			go serveFixture(c, protocol, log)
		}
	}
	source := os.Getenv("TFW_SOURCE")
	if source == "" {
		host, _, _ := net.SplitHostPort(address)
		source = "10.90.0.2"
		if strings.Contains(host, ":") {
			source = "fd90::2"
		}
	}
	local, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(source, "0"))
	if err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: local}
	c, err := dialer.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	forbidden := os.Getenv("TFW_FORBIDDEN") == "true"
	if protocol == "redis" {
		command := "PING"
		if forbidden {
			command = "FLUSHALL"
		}
		wire := fmt.Sprintf("*1\r\n$%d\r\n%s\r\n", len(command), command)
		if _, err = c.Write([]byte(wire)); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || line != "+OK\r\n" {
			t.Fatalf("Redis reply %q: %v", line, err)
		}
		return
	}
	// Captured, CRC-valid READ-all and WRITE-time requests from the gateway tests.
	hexRequest := "05640bc403000400ef7ac1c1013c0206b576"
	if forbidden {
		hexRequest = "056412c403000400152dc1c10232010701fa7d0b460d01c863"
	}
	wire, _ := hex.DecodeString(hexRequest)
	if _, err = c.Write(wire); err != nil {
		t.Fatal(err)
	}
	data, err := readDNPFixture(c)
	if err != nil || len(data) < 5 || data[2] != 129 {
		t.Fatalf("DNP3 response %x: %v", data, err)
	}
}

func appendLog(path, line string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err = f.WriteString(line + "\n"); err != nil {
		panic(err)
	}
}

func serveFixture(c net.Conn, protocol, path string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	peer, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	if protocol == "redis" {
		r := bufio.NewReader(c)
		line, err := r.ReadString('\n')
		if err != nil || line != "*1\r\n" {
			return
		}
		line, err = r.ReadString('\n')
		if err != nil || len(line) < 4 {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
		if err != nil || n < 1 || n > 64 {
			return
		}
		b := make([]byte, n+2)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		appendLog(path, "redis:"+string(b[:n])+" peer="+peer)
		_, _ = c.Write([]byte("+OK\r\n"))
		return
	}
	data, err := readDNPFixture(c)
	if err != nil || len(data) < 3 {
		return
	}
	appendLog(path, fmt.Sprintf("dnp3:%d peer=%s", data[2], peer))
	_, _ = c.Write(dnpResponse(data[1] & 15))
}

func dnpCRCFixture(b []byte) uint16 {
	var crc uint16
	for _, v := range b {
		crc ^= uint16(v)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	return ^crc
}
func dnpResponse(sequence byte) []byte {
	data := []byte{0xc0, 0xc0 | sequence, 129, 0, 0}
	b := []byte{5, 0x64, byte(5 + len(data)), 0x44, 4, 0, 3, 0}
	b = binary.LittleEndian.AppendUint16(b, dnpCRCFixture(b))
	b = append(b, data...)
	return binary.LittleEndian.AppendUint16(b, dnpCRCFixture(data))
}
func readDNPFixture(r io.Reader) ([]byte, error) {
	h := make([]byte, 10)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	n := int(h[2]) - 5
	if n < 0 || h[0] != 5 || h[1] != 0x64 || binary.LittleEndian.Uint16(h[8:]) != dnpCRCFixture(h[:8]) {
		return nil, fmt.Errorf("bad DNP header")
	}
	var data []byte
	for n > 0 {
		size := min(n, 16)
		b := make([]byte, size+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		if binary.LittleEndian.Uint16(b[size:]) != dnpCRCFixture(b[:size]) {
			return nil, fmt.Errorf("bad DNP data CRC")
		}
		data = append(data, b[:size]...)
		n -= size
	}
	return data, nil
}
