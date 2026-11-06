//go:build linux && integration

package enforcer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Run only inside a disposable privileged container: ENFORCER_NETNS_TEST=1
// go test -tags integration ./internal/enforcer. The lab creates three named
// namespaces and two veth pairs; nft is invoked only inside the target namespace.
func TestNFTNetworkNamespace(t *testing.T) {
	if os.Getenv("ENFORCER_NETNS_TEST") != "1" {
		t.Skip("set ENFORCER_NETNS_TEST=1 inside a disposable privileged container")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}
	for _, bin := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	target := "nce_" + strconv.Itoa(os.Getpid())
	peer := target + "p"
	run("netns", "add", target)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", target).Run() })
	run("netns", "add", peer)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", peer).Run() })
	run("-n", target, "link", "add", "ingress", "type", "veth", "peer", "name", "egress", "netns", peer)
	for _, n := range []string{target, peer} {
		run("-n", n, "link", "set", "lo", "up")
	}
	run("-n", target, "addr", "add", "10.207.0.1/24", "dev", "ingress")
	run("-n", target, "addr", "add", "10.207.0.3/24", "dev", "ingress")
	run("-n", peer, "addr", "add", "10.207.0.2/24", "dev", "egress")
	run("-n", target, "-6", "addr", "add", "fd42:207::1/64", "dev", "ingress", "nodad")
	run("-n", peer, "-6", "addr", "add", "fd42:207::2/64", "dev", "egress", "nodad")
	run("-n", target, "link", "set", "ingress", "up")
	run("-n", peer, "link", "set", "egress", "up")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	startServer := func(namespace, addresses, udp string) {
		t.Helper()
		server := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, exe, "-test.run=^TestEnforcerLabHelper$")
		server.Env = append(os.Environ(), "ENFORCER_HELPER=serve", "ENFORCER_LISTEN="+addresses, "ENFORCER_UDP="+udp)
		stdout, e := server.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		server.Stderr = os.Stderr
		if e = server.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
		ready := make(chan string, 1)
		go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
		select {
		case line := <-ready:
			if line != "ready\n" {
				t.Fatal("server failed", line)
			}
		case <-ctx.Done():
			t.Fatal("server readiness timeout")
		}
	}
	startServer(target, "10.207.0.1:18080,10.207.0.1:18081,10.207.0.3:18080,[fd42:207::1]:18080", "10.207.0.1:18080")
	probe := func(address, protocol string, blocked bool) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", peer, exe, "-test.run=^TestEnforcerLabHelper$")
		cmd.Env = append(os.Environ(), "ENFORCER_HELPER=probe", "ENFORCER_ADDRESS="+address, "ENFORCER_PROTOCOL="+protocol, fmt.Sprintf("ENFORCER_BLOCKED=%t", blocked))
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("probe %s/%s blocked=%t: %v %s", protocol, address, blocked, e, out)
		}
	}
	cfg := testConfig()
	cfg.DryRun = false
	cfg.Namespace = target
	cfg.Scope = Scope{Hook: "input", Interface: "ingress", DestinationCIDR: "10.207.0.1/32", Protocol: "tcp", Port: 18080}
	c := controller(t, cfg, nil)
	probe("10.207.0.1:18080", "tcp", false)
	l, err := c.Create(ctx, "block", "10.207.0.2", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	probe("10.207.0.1:18080", "tcp", true)
	probe("10.207.0.1:18081", "tcp", false)
	probe("10.207.0.3:18080", "tcp", false)
	probe("10.207.0.1:18080", "udp", false)
	if err = c.Delete(ctx, l.ID); err != nil {
		t.Fatal(err)
	}
	probe("10.207.0.1:18080", "tcp", false)
	l, err = c.Create(ctx, "expire", "10.207.0.2", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	probe("10.207.0.1:18080", "tcp", true)
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(l.ExpiresAt) + 250*time.Millisecond)
	// No controller is alive: expiry must be entirely kernel-enforced.
	probe("10.207.0.1:18080", "tcp", false)
	c = controller(t, cfg, nil)
	ls, err := c.List(ctx)
	if err != nil || len(ls) != 0 {
		t.Fatal("expired rules not reconciled", ls, err)
	}
	// A colliding table is never flushed or adopted.
	collision := cfg
	collision.Table = "netcap_firewall_collision"
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", target, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader("add table inet " + collision.Table + " { comment \"other-owner\"; }\n")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	if x, e := New(collision, nil); e == nil {
		_ = x.Close()
		t.Fatal("adopted collision")
	}
	out := run("netns", "exec", target, "nft", "list", "table", "inet", collision.Table)
	if !strings.Contains(out, "other-owner") {
		t.Fatal("modified colliding table", out)
	}
	v6cfg := cfg
	v6cfg.Table = "netcap_firewall_v6"
	v6cfg.Scope.DestinationCIDR = "fd42:207::1/128"
	v6 := controller(t, v6cfg, nil)
	probe("[fd42:207::1]:18080", "tcp", false)
	if _, err = v6.Create(ctx, "v6", "fd42:207::2", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	probe("[fd42:207::1]:18080", "tcp", true)
	if err = v6.Delete(ctx, "v6"); err != nil {
		t.Fatal(err)
	}
	probe("[fd42:207::1]:18080", "tcp", false)
	udpcfg := cfg
	udpcfg.Table = "netcap_firewall_udp"
	udpcfg.Scope.Protocol = "udp"
	uc := controller(t, udpcfg, nil)
	if _, err = uc.Create(ctx, "udp", "10.207.0.2", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	probe("10.207.0.1:18080", "udp", true)
	probe("10.207.0.1:18080", "tcp", false)
	if err = uc.Delete(ctx, "udp"); err != nil {
		t.Fatal(err)
	}
	probe("10.207.0.1:18080", "udp", false)
	wrong := cfg
	wrong.Table = "netcap_firewall_interface"
	wrong.Scope.Interface = "unmatched"
	wc := controller(t, wrong, nil)
	if _, err = wc.Create(ctx, "interface", "10.207.0.2", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	probe("10.207.0.1:18080", "tcp", false)
	downstream := target + "d"
	run("netns", "add", downstream)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", downstream).Run() })
	run("-n", target, "link", "add", "downlink", "type", "veth", "peer", "name", "service", "netns", downstream)
	run("-n", target, "addr", "add", "10.208.0.1/24", "dev", "downlink")
	run("-n", target, "link", "set", "downlink", "up")
	run("-n", downstream, "addr", "add", "10.208.0.2/24", "dev", "service")
	run("-n", downstream, "link", "set", "service", "up")
	run("-n", peer, "route", "add", "10.208.0.0/24", "via", "10.207.0.1")
	run("-n", downstream, "route", "add", "10.207.0.0/24", "via", "10.208.0.1")
	run("netns", "exec", target, "sysctl", "-w", "net.ipv4.ip_forward=1")
	startServer(downstream, "10.208.0.2:18080,10.208.0.2:18081", "")
	fcfg := cfg
	fcfg.Table = "netcap_firewall_forward"
	fcfg.Scope.Hook = "forward"
	fcfg.Scope.DestinationCIDR = "10.208.0.2/32"
	fc := controller(t, fcfg, nil)
	probe("10.208.0.2:18080", "tcp", false)
	if _, err = fc.Create(ctx, "forward", "10.207.0.2", 10*time.Second); err != nil {
		t.Fatal(err)
	}
	probe("10.208.0.2:18080", "tcp", true)
	probe("10.208.0.2:18081", "tcp", false)
	probe("10.207.0.1:18080", "tcp", false)
	if err = fc.Delete(ctx, "forward"); err != nil {
		t.Fatal(err)
	}
	probe("10.208.0.2:18080", "tcp", false)
	t.Log("verified real kernel: IPv4/IPv6 input TCP, IPv4 input UDP and forward TCP drops, interface/port/destination/protocol isolation, exact deletion, timeout after Close, restart cleanup, ownership collision")
}

func TestEnforcerLabHelper(t *testing.T) {
	switch os.Getenv("ENFORCER_HELPER") {
	case "serve":
		for _, addr := range strings.Split(os.Getenv("ENFORCER_LISTEN"), ",") {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, e := ln.Accept()
					if e != nil {
						return
					}
					_ = c.Close()
				}
			}()
		}
		if address := os.Getenv("ENFORCER_UDP"); address != "" {
			pc, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			go func() {
				buf := make([]byte, 64)
				for {
					n, a, e := pc.ReadFrom(buf)
					if e != nil {
						return
					}
					_, _ = pc.WriteTo(buf[:n], a)
				}
			}()
		}
		fmt.Println("ready")
		select {}
	case "probe":
		protocol := os.Getenv("ENFORCER_PROTOCOL")
		c, err := net.DialTimeout(protocol, os.Getenv("ENFORCER_ADDRESS"), 500*time.Millisecond)
		if err == nil {
			defer c.Close()
			if protocol == "udp" {
				_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
				_, err = c.Write([]byte("ping"))
				if err == nil {
					_, err = io.ReadFull(c, make([]byte, 4))
				}
			}
		}
		blocked := os.Getenv("ENFORCER_BLOCKED") == "true"
		if (err != nil) != blocked {
			t.Fatalf("blocked=%t, result=%v", blocked, err)
		}
	}
}
