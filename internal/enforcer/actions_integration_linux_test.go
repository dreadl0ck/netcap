//go:build linux && integration

package enforcer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This suite is explicitly gated and creates only disposable named namespaces.
func TestTypedActionsKernel(t *testing.T) {
	if os.Getenv("ENFORCER_NETNS_TEST") != "1" {
		t.Skip("requires disposable privileged Docker lab")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("Docker-only qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	baseline, err := exec.CommandContext(ctx, "nft", "-j", "list", "ruleset").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		after, err := exec.Command("nft", "-j", "list", "ruleset").Output()
		if err != nil || string(after) != string(baseline) {
			t.Fatalf("container default namespace changed: %v", err)
		}
	})
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
		return string(out)
	}
	target, peer := "nca_target", "nca_peer"
	for _, n := range []string{target, peer} {
		run("netns", "add", n)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", n).Run() })
		run("-n", n, "link", "set", "lo", "up")
	}
	run("-n", target, "link", "add", "ingress", "type", "veth", "peer", "name", "egress", "netns", peer)
	for _, x := range []struct{ ns, dev, v4, v6 string }{{target, "ingress", "10.209.0.1/24", "fd42:209::1/64"}, {peer, "egress", "10.209.0.2/24", "fd42:209::2/64"}} {
		run("-n", x.ns, "addr", "add", x.v4, "dev", x.dev)
		run("-n", x.ns, "-6", "addr", "add", x.v6, "dev", x.dev, "nodad")
		run("-n", x.ns, "link", "set", x.dev, "up")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(ns, mode string, env ...string) (*exec.Cmd, *bufio.Reader, io.WriteCloser) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, exe, "-test.run=^TestTypedActionsHelper$")
		cmd.Env = append(os.Environ(), append([]string{"NCA_MODE=" + mode}, env...)...)
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		reader := bufio.NewReader(stdout)
		line, err := reader.ReadString('\n')
		if err != nil || line != "ready\n" {
			t.Fatalf("helper %s: %q %v", mode, line, err)
		}
		return cmd, reader, stdin
	}
	start(target, "serve")
	probe := func(addr, proto string, port, n int) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "ip", "netns", "exec", peer, exe, "-test.run=^TestTypedActionsHelper$")
		cmd.Env = append(os.Environ(), "NCA_MODE=probe", "NCA_ADDRESS="+addr, "NCA_PROTOCOL="+proto, "NCA_PORT="+strconv.Itoa(port), "NCA_COUNT="+strconv.Itoa(n))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("probe %s: %v %s", addr, err, out)
		}
		return strings.TrimSpace(strings.Split(string(out), "\n")[0])
	}
	for family, addresses := range map[string][2]string{"v4": {"10.209.0.1", "10.209.0.2"}, "v6": {"fd42:209::1", "fd42:209::2"}} {
		t.Run(family, func(t *testing.T) {
			dst, src := addresses[0], addresses[1]
			bits := "/32"
			if family == "v6" {
				bits = "/128"
			}
			address := func(port int) string { return net.JoinHostPort(dst, strconv.Itoa(port)) }
			clientPort := 31000
			if family == "v6" {
				clientPort = 32000
			}
			cfg := Config{Token: strings.Repeat("t", 32), Namespace: target, Table: "netcap_firewall_actions_" + family, Scope: Scope{Hook: "input", Interface: "ingress", DestinationCIDR: dst + bits, Protocol: "tcp", Port: 18080}, ProtectedServices: []Service{{"tcp", 18022}}, Profiles: map[string]Profile{
				"isolate": {Kind: Quarantine, Services: []Service{{"tcp", 18080}, {"udp", 18080}, {"tcp", 18081}}},
				"packets": {Kind: RateSource, Services: []Service{{"udp", 18080}}, Unit: "packets", Rate: 1, Burst: 3},
				"bytes":   {Kind: RateSource, Services: []Service{{"udp", 18080}}, Unit: "bytes", Rate: 1, Burst: 800},
			}}
			c, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			create := func(id string, a Action, ttl time.Duration) Lease {
				t.Helper()
				l, e := c.CreateActionUntil(ctx, id, src, time.Now().UTC().Add(ttl), a)
				if e != nil {
					t.Fatal(e)
				}
				return l
			}
			check := func(port int, proto, want string) {
				t.Helper()
				if got := probe(address(port), proto, 0, 1); got != want {
					t.Fatalf("%s/%d got %q want %q", proto, port, got, want)
				}
			}
			check(18080, "tcp", "ok")
			check(18080, "udp", "1")
			create("q", Action{Kind: Quarantine, Profile: "isolate"}, 10*time.Second)
			check(18080, "tcp", "timeout")
			check(18081, "tcp", "timeout")
			check(18080, "udp", "0")
			check(18022, "tcp", "ok")
			check(18082, "tcp", "ok")
			if err = c.Delete(ctx, "q"); err != nil {
				t.Fatal(err)
			}
			check(18080, "tcp", "ok")
			// Two established connections differ only by client port.
			_, targetReader, targetInput := start(peer, "hold", "NCA_ADDRESS="+address(18080), "NCA_PORT="+strconv.Itoa(clientPort+1))
			_, otherReader, otherInput := start(peer, "hold", "NCA_ADDRESS="+address(18080), "NCA_PORT="+strconv.Itoa(clientPort+2))
			flow := Flow{Destination: dst, Protocol: "tcp", SourcePort: uint16(clientPort + 1), DestinationPort: 18080}
			create("reject", Action{Kind: RejectFlow, Flow: flow}, 10*time.Second)
			_, _ = io.WriteString(targetInput, "probe\n")
			result, _ := targetReader.ReadString('\n')
			if strings.TrimSpace(result) != "reset" {
				t.Fatalf("established flow wasn't reset: %q", result)
			}
			_, _ = io.WriteString(otherInput, "probe\n")
			result, _ = otherReader.ReadString('\n')
			if strings.TrimSpace(result) != "ok" {
				t.Fatalf("unrelated flow affected: %q", result)
			}
			if err = c.Delete(ctx, "reject"); err != nil {
				t.Fatal(err)
			}
			flow.SourcePort = uint16(clientPort + 3)
			create("drop", Action{Kind: DropFlow, Flow: flow}, 10*time.Second)
			if got := probe(address(18080), "tcp", clientPort+3, 1); got != "timeout" {
				t.Fatal("flow drop:", got)
			}
			check(18080, "tcp", "ok")
			if err = c.Delete(ctx, "drop"); err != nil {
				t.Fatal(err)
			}
			for _, rate := range []struct {
				name string
				want string
			}{{"packets", "3"}, {"bytes", map[string]string{"v4": "6", "v6": "5"}[family]}} {
				create(rate.name, Action{Kind: RateSource, Profile: rate.name}, 10*time.Second)
				if got := probe(address(18080), "udp", 0, 10); got != rate.want {
					t.Fatalf("%s exact burst: got %s want %s", rate.name, got, rate.want)
				}
				if rate.name == "packets" {
					if got := probe(address(18080), "udp", 0, 3); got != "0" {
						t.Fatal("empty packet bucket admitted burst:", got)
					}
					time.Sleep(1100 * time.Millisecond)
					if got := probe(address(18080), "udp", 0, 3); got != "1" {
						t.Fatal("packet refill:", got)
					}
				}
				check(18022, "tcp", "ok")
				if err = c.Delete(ctx, rate.name); err != nil {
					t.Fatal(err)
				}
			}
			// Recover from an actual killed controller with unchanged kernel deadline.
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			cfg.Table += "_crash"
			cfg.Profiles = map[string]Profile{"isolate": cfg.Profiles["isolate"]}
			raw, _ := json.Marshal(cfg)
			// Run controller outside the target namespace: default-netns refusal remains enabled.
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestTypedActionsHelper$")
			cmd.Env = append(os.Environ(), "NCA_MODE=controller", "NCA_CONFIG="+string(raw), "NCA_SOURCE="+src)
			stdout, _ := cmd.StdoutPipe()
			cmd.Stderr = os.Stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			reader := bufio.NewReader(stdout)
			line, _ := reader.ReadString('\n')
			var lease Lease
			if err = json.Unmarshal([]byte(line), &lease); err != nil {
				t.Fatalf("controller: %q %v", line, err)
			}
			check(18080, "tcp", "timeout")
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal("controller was not alive for SIGKILL:", err)
			}
			err = cmd.Wait()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("controller did not exit from SIGKILL: %v", err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("controller exit wasn't SIGKILL: %v", err)
			}
			check(18022, "tcp", "ok")
			check(18080, "tcp", "timeout")
			recovered, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			ls, err := recovered.List(ctx)
			if err != nil || len(ls) != 1 || !ls[0].ExpiresAt.Equal(lease.ExpiresAt) || ls[0].Action != lease.Action {
				t.Fatalf("crash recovery: %+v %v", ls, err)
			}
			_ = recovered.Close()
			time.Sleep(time.Until(lease.ExpiresAt) + 100*time.Millisecond)
			check(18080, "tcp", "ok")
			check(18080, "udp", "1")
			check(18022, "tcp", "ok")
			udpCfg := cfg
			udpCfg.Table = "netcap_firewall_udp_actions_" + family
			udpCfg.Scope.Protocol = "udp"
			udp, err := New(udpCfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			udpFlow := Flow{Destination: dst, Protocol: "udp", SourcePort: uint16(clientPort + 4), DestinationPort: 18080}
			if _, err = udp.CreateActionUntil(ctx, "udp-drop", src, time.Now().Add(10*time.Second), Action{Kind: DropFlow, Flow: udpFlow}); err != nil {
				t.Fatal(err)
			}
			if got := probe(address(18080), "udp", clientPort+4, 1); got != "0" {
				t.Fatal("UDP flow drop:", got)
			}
			check(18080, "udp", "1")
			if err = udp.Delete(ctx, "udp-drop"); err != nil {
				t.Fatal(err)
			}
			if _, err = udp.CreateActionUntil(ctx, "udp-reject", src, time.Now().Add(10*time.Second), Action{Kind: RejectFlow, Flow: udpFlow}); err != nil {
				t.Fatal(err)
			}
			if got := probe(address(18080), "udp-status", clientPort+4, 1); got != "refused" {
				t.Fatal("UDP kernel rejection:", got)
			}
			check(18080, "udp", "1")
			if err = udp.Delete(ctx, "udp-reject"); err != nil {
				t.Fatal(err)
			}
			_ = udp.Close()
			// Dedicated DNAT scope never accepts filter actions. Test a new source port after expiry.
			cfg.Table = "netcap_firewall_nat_" + family
			cfg.Scope.Hook = "prerouting"
			cfg.Profiles = map[string]Profile{"gateway": {Kind: RedirectSource, Services: []Service{{"tcp", 18080}}, Destination: dst, Port: 18082}}
			nat, err := New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().UTC().Add(2 * time.Second)
			if _, err = nat.CreateActionUntil(ctx, "route", src, deadline, Action{Kind: RedirectSource, Profile: "gateway"}); err != nil {
				script, _ := nat.backend.(*NFTBackend).applyScript(Lease{ID: "diagnose", Source: src, Scope: cfg.Scope, TTLSeconds: 10, ExpiresAt: time.Now().Add(10 * time.Second), Action: Action{Kind: RedirectSource, Profile: "gateway"}}, time.Now())
				cmd := exec.CommandContext(ctx, "ip", "netns", "exec", target, "nft", "-c", "-f", "-")
				cmd.Stdin = strings.NewReader(script)
				output, _ := cmd.CombinedOutput()
				t.Fatalf("%v\n%s\n%s", err, script, output)
			}
			if got := probe(address(18080), "tcp-marker", 0, 1); got != "18082" {
				t.Fatalf("redirect destination: %q", got)
			}
			_ = nat.Close()
			time.Sleep(time.Until(deadline) + 100*time.Millisecond)
			if got := probe(address(18080), "tcp-marker", 0, 1); got != "18080" {
				t.Fatalf("redirect after expiry: %q", got)
			}
			cfg.Table += "_udp"
			cfg.Scope.Protocol = "udp"
			cfg.Profiles["gateway"] = Profile{Kind: RedirectSource, Services: []Service{{"udp", 18080}}, Destination: dst, Port: 18082}
			nat, err = New(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().UTC().Add(2 * time.Second)
			if _, err = nat.CreateActionUntil(ctx, "route-udp", src, deadline, Action{Kind: RedirectSource, Profile: "gateway"}); err != nil {
				t.Fatal(err)
			}
			if got := probe(address(18080), "udp-marker", 0, 1); got != "18082" {
				t.Fatalf("UDP redirect destination: %q", got)
			}
			_ = nat.Close()
			time.Sleep(time.Until(deadline) + 100*time.Millisecond)
			check(18080, "udp", "1")
			t.Log("kernel verified: multi-service quarantine; management/unrelated service survive; established TCP exact-flow reset; flow drop isolation; packet burst=3; byte burst=" + map[string]string{"v4": "6", "v6": "5"}[family] + "; killed-controller recovery without deadline extension; expiry; new-connection DNAT/expiry")
		})
	}
}

func TestTypedActionsHelper(t *testing.T) {
	mode := os.Getenv("NCA_MODE")
	if mode == "" {
		return
	}
	if mode == "controller" {
		var cfg Config
		if err := json.Unmarshal([]byte(os.Getenv("NCA_CONFIG")), &cfg); err != nil {
			t.Fatal(err)
		}
		c, err := New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		l, err := c.CreateActionUntil(context.Background(), "crash", os.Getenv("NCA_SOURCE"), time.Now().UTC().Add(3*time.Second), Action{Kind: Quarantine, Profile: "isolate"})
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(l)
		for {
			time.Sleep(time.Hour)
		}
	}
	if mode == "serve" {
		for _, ip := range []string{"10.209.0.1", "fd42:209::1"} {
			for _, port := range []int{18080, 18081, 18082, 18022} {
				address := net.JoinHostPort(ip, strconv.Itoa(port))
				ln, err := net.Listen("tcp", address)
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
						go func() {
							defer c.Close()
							b := make([]byte, 100)
							for {
								_, e := c.Read(b)
								if e != nil {
									return
								}
								_, _ = fmt.Fprintln(c, port)
							}
						}()
					}
				}()
				pc, err := net.ListenPacket("udp", address)
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				go func() {
					b := make([]byte, 2048)
					for {
						n, a, e := pc.ReadFrom(b)
						if e != nil {
							return
						}
						if port == 18082 {
							_, _ = pc.WriteTo([]byte("18082"), a)
						} else {
							_, _ = pc.WriteTo(b[:n], a)
						}
					}
				}()
			}
		}
		fmt.Println("ready")
		select {}
	}
	addr := os.Getenv("NCA_ADDRESS")
	proto := os.Getenv("NCA_PROTOCOL")
	if proto == "" {
		proto = "tcp"
	}
	port, _ := strconv.Atoi(os.Getenv("NCA_PORT"))
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	if port != 0 {
		dialer.LocalAddr = &net.TCPAddr{Port: port}
		if strings.HasPrefix(proto, "udp") {
			dialer.LocalAddr = &net.UDPAddr{Port: port}
		}
	}
	network := "tcp"
	if strings.HasPrefix(proto, "udp") {
		network = "udp"
	}
	c, err := dialer.Dial(network, addr)
	classify := func(err error) string {
		if err == nil {
			return "ok"
		}
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return "timeout"
		}
		if strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "broken pipe") {
			return "reset"
		}
		if strings.Contains(err.Error(), "refused") {
			return "refused"
		}
		return err.Error()
	}
	if err != nil {
		fmt.Println(classify(err))
		return
	}
	defer c.Close()
	if mode == "hold" {
		fmt.Println("ready")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	_ = c.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if strings.HasPrefix(proto, "udp") {
		if proto == "udp-status" || proto == "udp-marker" {
			_, err = c.Write(make([]byte, 100))
			b := make([]byte, 2048)
			if err == nil {
				n, err := c.Read(b)
				if proto == "udp-marker" && err == nil {
					fmt.Println(string(b[:n]))
					return
				}
				fmt.Println(classify(err))
				return
			}
			fmt.Println(classify(err))
			return
		}
		n, _ := strconv.Atoi(os.Getenv("NCA_COUNT"))
		for j := 0; j < n; j++ {
			_, _ = c.Write(make([]byte, 100))
		}
		count := 0
		b := make([]byte, 2048)
		for {
			if _, e := c.Read(b); e != nil {
				break
			}
			count++
		}
		fmt.Println(count)
		return
	}
	_, err = c.Write([]byte("probe"))
	b := make([]byte, 100)
	n := 0
	if err == nil {
		n, err = c.Read(b)
	}
	if proto == "tcp-marker" && err == nil {
		fmt.Println(strings.TrimSpace(string(b[:n])))
		return
	}
	fmt.Println(classify(err))
}
