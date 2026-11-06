// Package firewall supplies the shared CLI for the standalone and net commands.
package firewall

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dreadl0ck/netcap/internal/enforcer"
	"github.com/dreadl0ck/netcap/internal/gateway"
	"github.com/dreadl0ck/netcap/internal/policy"
	"github.com/dreadl0ck/netcap/internal/policycontrol"
	"github.com/dreadl0ck/netcap/internal/waf"
	"github.com/urfave/cli/v3"
)

func configFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "config", Required: true, Usage: "runtime YAML or JSON file"},
		&cli.BoolFlag{Name: "managed", Usage: "allow authenticated policy activation; requires state-dir and admin token"},
		&cli.StringFlag{Name: "state-dir", Usage: "private durable policy directory"},
		&cli.StringFlag{Name: "admin-cert", Usage: "administrative TLS certificate"},
		&cli.StringFlag{Name: "admin-key", Usage: "administrative TLS private key"},
	}
}

// GetCommand also powers the thin executable without capture or DPI dependencies.
func GetCommand() *cli.Command {
	return &cli.Command{Name: "firewall", Usage: "protocol-aware application firewall", Commands: []*cli.Command{
		{Name: "serve", Usage: "serve the enforcing HTTP reverse proxy", Flags: configFlags(), Action: withSignals(serve)},
		{Name: "validate", Usage: "validate runtime, policy and enabled inspection engines without listening", Flags: configFlags(), Action: validate},
		{Name: "mcp", Usage: "stdio MCP for isolated policy authoring and replay (not a running target)", Flags: configFlags(), Action: withSignals(stdio)},
		{Name: "healthcheck", Flags: []cli.Flag{&cli.StringFlag{Name: "url", Value: "http://127.0.0.1:9090/readyz"}}, Action: healthcheck},
		{Name: "gateway", Usage: "run a bounded plaintext DNS or Modbus gateway", Flags: []cli.Flag{
			&cli.StringFlag{Name: "protocol", Required: true}, &cli.StringFlag{Name: "listen", Required: true},
			&cli.StringFlag{Name: "upstream", Required: true}, &cli.StringFlag{Name: "policy", Required: true},
			&cli.StringSliceFlag{Name: "allow-client", Usage: "permitted source CIDR (default loopback only)"},
		}, Action: withSignals(runGateway)},
		{Name: "enforcer", Usage: "explicit scoped nftables leases in a named Linux lab namespace", Flags: []cli.Flag{
			&cli.StringFlag{Name: "listen", Value: "127.0.0.1:9091"}, &cli.StringFlag{Name: "namespace"},
			&cli.StringFlag{Name: "table", Value: "netcap_firewall_leases"}, &cli.StringFlag{Name: "interface", Required: true},
			&cli.StringFlag{Name: "destination", Required: true}, &cli.StringFlag{Name: "protocol", Value: "tcp"},
			&cli.StringFlag{Name: "hook", Value: "forward"}, &cli.UintFlag{Name: "port", Required: true},
			&cli.StringSliceFlag{Name: "protected-cidr"}, &cli.BoolFlag{Name: "dry-run"}, &cli.StringFlag{Name: "state-file"},
		}, Action: withSignals(runEnforcer)},
		{Name: "version", Action: func(_ context.Context, c *cli.Command) error {
			return json.NewEncoder(c.Root().Writer).Encode(map[string]any{"version": "netcap-firewall/v1", "policy": "netcap-policy/v1", "protocols": []string{"http", "modbus", "dns"}})
		}},
	}}
}

func withSignals(action cli.ActionFunc) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return action(ctx, c)
	}
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	return b, err
}

func loadPolicy(path string) (*policy.Compiled, error) {
	b, err := readBounded(path, policy.MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	p, err := policy.Parse(b)
	if err != nil {
		return nil, err
	}
	return policy.Compile(p)
}

func load(path string) (waf.Config, *policy.Compiled, error) {
	b, err := readBounded(path, 64<<10)
	if err != nil {
		return waf.Config{}, nil, err
	}
	c, err := waf.LoadConfig(b)
	if err != nil {
		return c, nil, err
	}
	if c.PolicyFile == "" {
		return c, nil, errors.New("policyFile required")
	}
	if !filepath.IsAbs(c.PolicyFile) {
		c.PolicyFile = filepath.Join(filepath.Dir(path), c.PolicyFile)
	}
	p, err := loadPolicy(c.PolicyFile)
	return c, p, err
}

func validate(_ context.Context, c *cli.Command) error {
	cfg, p, err := load(c.String("config"))
	if err != nil {
		return err
	}
	f, err := waf.New(cfg, p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(c.Root().Writer, "valid policy revision %s\n", p.Revision())
	return err
}

func adminConfig(c *cli.Command) policycontrol.Config {
	return policycontrol.Config{Token: os.Getenv("NETCAP_FIREWALL_ADMIN_TOKEN"), Managed: c.Bool("managed"), StateDir: c.String("state-dir")}
}

func loopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func serve(ctx context.Context, c *cli.Command) error {
	cfg, p, err := load(c.String("config"))
	if err != nil {
		return err
	}
	f, err := waf.New(cfg, p)
	if err != nil {
		return err
	}
	defer f.Close()
	admin := http.NewServeMux()
	admin.Handle("/", f.AdminHandler())
	ac := adminConfig(c)
	if ac.Managed && ac.Token == "" {
		return errors.New("managed mode requires NETCAP_FIREWALL_ADMIN_TOKEN")
	}
	if ac.Token != "" {
		if len(ac.Token) < 32 {
			return errors.New("administrative token requires at least 32 bytes")
		}
		if !loopbackAddress(cfg.AdminListen) && (c.String("admin-cert") == "" || c.String("admin-key") == "") {
			return errors.New("network-accessible policy management requires admin-cert and admin-key; otherwise bind adminListen to loopback")
		}
		s, err := policycontrol.New(ac, f)
		if err != nil {
			return err
		}
		defer s.Close()
		admin.Handle("/api/v1/policy/", s.Handler())
		admin.Handle("/mcp", s.Handler())
	}
	if (c.String("admin-cert") == "") != (c.String("admin-key") == "") {
		return errors.New("admin-cert and admin-key must be paired")
	}
	data := &http.Server{Addr: cfg.Listen, Handler: f, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	management := &http.Server{Addr: cfg.AdminListen, Handler: admin, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	dl, err := net.Listen("tcp", data.Addr)
	if err != nil {
		return err
	}
	defer dl.Close()
	al, err := net.Listen("tcp", management.Addr)
	if err != nil {
		return err
	}
	defer al.Close()
	if cfg.TLSCert != "" {
		if _, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			return err
		}
	}
	if c.String("admin-cert") != "" {
		if _, err := tls.LoadX509KeyPair(c.String("admin-cert"), c.String("admin-key")); err != nil {
			return err
		}
	}
	auditCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := f.WriteAudit(auditCtx, c.Root().Writer); err != nil && auditCtx.Err() == nil {
			fmt.Fprintln(c.Root().ErrWriter, "firewall audit sink failed:", err)
		}
	}()
	errs := make(chan error, 2)
	go func() {
		if cfg.TLSCert != "" {
			errs <- data.ServeTLS(dl, cfg.TLSCert, cfg.TLSKey)
		} else {
			errs <- data.Serve(dl)
		}
	}()
	go func() {
		if c.String("admin-cert") != "" {
			errs <- management.ServeTLS(al, c.String("admin-cert"), c.String("admin-key"))
		} else {
			errs <- management.Serve(al)
		}
	}()
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	f.SetDraining(true)
	shutdown, stop := context.WithTimeout(context.Background(), 45*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- data.Shutdown(shutdown) }()
	adminErr := management.Shutdown(shutdown)
	dataErr := <-done
	// Shutdown does not close hijacked WebSocket connections.
	_ = f.Close()
	_ = data.Close()
	_ = management.Close()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, dataErr, adminErr)
}

type localTarget struct {
	p atomic.Pointer[policy.Compiled]
}

func (t *localTarget) Policy() *policy.Compiled     { return t.p.Load() }
func (t *localTarget) SetPolicy(p *policy.Compiled) { t.p.Store(p) }

func stdio(ctx context.Context, c *cli.Command) error {
	_, p, err := load(c.String("config"))
	if err != nil {
		return err
	}
	if c.Bool("managed") {
		return errors.New("stdio is isolated authoring/replay; use the running target's authenticated HTTP MCP for activation")
	}
	t := &localTarget{}
	t.SetPolicy(p)
	s, err := policycontrol.New(policycontrol.Config{Token: "local-stdio-read-only-principal", ReadOnly: true}, t)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.ServeStdio(ctx)
}

func healthcheck(ctx context.Context, c *cli.Command) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.String("url"), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("healthcheck status %d", res.StatusCode)
	}
	return nil
}

func runGateway(ctx context.Context, c *cli.Command) error {
	p, err := loadPolicy(c.String("policy"))
	if err != nil {
		return err
	}
	cfg := gateway.Config{Protocol: c.String("protocol"), Listen: c.String("listen"), Upstream: c.String("upstream")}
	for _, v := range c.StringSlice("allow-client") {
		n, err := netip.ParsePrefix(v)
		if err != nil {
			return err
		}
		cfg.AllowedClients = append(cfg.AllowedClients, n)
	}
	return gateway.Run(ctx, cfg, p)
}

func runEnforcer(ctx context.Context, c *cli.Command) error {
	if !loopbackAddress(c.String("listen")) {
		return errors.New("enforcer listener must be a loopback IP; remote access requires an authenticated TLS tunnel")
	}
	if c.Uint("port") == 0 || c.Uint("port") > 65535 {
		return errors.New("port must be 1..65535")
	}
	cfg := enforcer.Config{Token: os.Getenv("NETCAP_FIREWALL_ADMIN_TOKEN"), Table: c.String("table"), Namespace: c.String("namespace"), ProtectedCIDRs: c.StringSlice("protected-cidr"), DryRun: c.Bool("dry-run"), StateFile: c.String("state-file"), Scope: enforcer.Scope{Hook: c.String("hook"), Interface: c.String("interface"), DestinationCIDR: c.String("destination"), Protocol: c.String("protocol"), Port: uint16(c.Uint("port"))}}
	e, err := enforcer.New(cfg, nil)
	if err != nil {
		return err
	}
	defer e.Close()
	srv := &http.Server{Addr: c.String("listen"), Handler: e.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer l.Close()
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(l) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdown)
		case err := <-errs:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			if err := e.Reconcile(ctx); err != nil {
				fmt.Fprintln(c.Root().ErrWriter, "enforcer reconciliation failed:", strings.TrimSpace(err.Error()))
			}
		}
	}
}
