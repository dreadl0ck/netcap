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
	"github.com/dreadl0ck/netcap/internal/firewalltransport"
	"github.com/dreadl0ck/netcap/internal/firewallui"
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
		&cli.StringFlag{Name: "fleet-agent-config", Usage: "strict JSON fleet agent bootstrap (tokenEnv)"},
		&cli.StringFlag{Name: "shared-rate-config", Usage: "strict JSON shared rate guard (tokenEnv)"},
		&cli.StringFlag{Name: "policy-state-config", Usage: "optional authoritative native thresholds/sequences client (tokenEnv)"},
		&cli.StringFlag{Name: "effects-config", Usage: "strict JSON response action scopes (tokenEnv); explicitly admits policy effects"},
		&cli.BoolFlag{Name: "websocket", Usage: "bounded messages; optional permessage-deflate without context takeover"},
		&cli.BoolFlag{Name: "grpc", Usage: "HTTP/2 message gates; http3 builds also enable HTTP/3 envelope ingress to HTTP/2 origin"},
		&cli.StringFlag{Name: "http3-listen", Usage: "optional UDP listener; requires http3 build tag and runtime TLS"},
	}
}

// GetCommand also powers the thin executable without capture or DPI dependencies.
func GetCommand() *cli.Command {
	return &cli.Command{Name: "firewall", Usage: "protocol-aware application firewall", Commands: []*cli.Command{
		{Name: "serve", Usage: "serve the enforcing HTTP reverse proxy", Flags: configFlags(), Action: withSignals(serve)},
		{Name: "validate", Usage: "validate runtime, policy and enabled inspection engines without listening", Flags: configFlags(), Action: validate},
		{Name: "mcp", Usage: "stdio MCP for isolated policy authoring and replay (not a running target)", Flags: configFlags(), Action: withSignals(stdio)},
		{Name: "healthcheck", Flags: []cli.Flag{&cli.StringFlag{Name: "url", Value: "http://127.0.0.1:9090/readyz"}}, Action: healthcheck},
		{Name: "gateway", Usage: "bounded DNS, Modbus, DNP3, Redis, MySQL, Postgres, SMTP, SMB2 or FTP gateway", Flags: gatewayFlags(), Action: withSignals(runGateway)},
		{Name: "network", Usage: "scoped Linux netns NFQUEUE firewall", Flags: networkFlags(), Action: withSignals(runNetwork)},
		{Name: "redirect", Usage: "place an already-running TCP protocol gateway on a scoped routed service path", Flags: redirectFlags(), Action: withSignals(runRedirect)},
		{Name: "fleet-controller", Usage: "authoritative fleet controller", Flags: serviceFlags(), Action: withSignals(runFleetController)},
		{Name: "sharedstate", Usage: "authoritative shared rate counters", Flags: serviceFlags(), Action: withSignals(runSharedState)},
		{Name: "policy-state", Usage: "authoritative scoped native policy thresholds and sequences", Flags: serviceFlags(), Action: withSignals(runPolicyState)},
		{Name: "backup", Usage: "offline snapshot (service must be stopped)", Flags: backupFlags(), Action: runBackup},
		{Name: "restore", Usage: "offline restore into empty state directory; fence old service first", Flags: restoreFlags(), Action: runRestore},
		{Name: "enforcer", Usage: "explicit scoped nftables leases in a named Linux lab namespace", Flags: []cli.Flag{
			&cli.StringFlag{Name: "listen", Value: "127.0.0.1:9091"}, &cli.StringFlag{Name: "namespace"},
			&cli.StringFlag{Name: "table", Value: "netcap_firewall_leases"}, &cli.StringFlag{Name: "interface", Required: true},
			&cli.StringFlag{Name: "destination", Required: true}, &cli.StringFlag{Name: "protocol", Value: "tcp"},
			&cli.StringFlag{Name: "hook", Value: "forward"}, &cli.UintFlag{Name: "port", Required: true},
			&cli.StringSliceFlag{Name: "protected-cidr"}, &cli.BoolFlag{Name: "dry-run"}, &cli.StringFlag{Name: "state-file"},
			&cli.StringFlag{Name: "tls-cert"}, &cli.StringFlag{Name: "tls-key"},
		}, Action: withSignals(runEnforcer)},
		{Name: "version", Action: func(_ context.Context, c *cli.Command) error {
			return json.NewEncoder(c.Root().Writer).Encode(map[string]any{"version": "netcap-firewall/v1", "policy": "netcap-policy/v1", "protocols": []string{"http", "modbus", "dns", "dns-tcp", "dns-tls", "redis", "postgres", "smtp", "mysql", "dnp3", "smb", "ftp", "network", "websocket", "grpc"}, "http3": firewalltransport.HTTP3Available, "http3_message_profile": firewalltransport.HTTP3Available, "websocket_compression": "permessage-deflate; no context takeover", "smb_profile": "plaintext SMB2/3 serial; signed bytes relayed unverified; transforms rejected", "ftp_profile": "EPSV stream; bounded complete transfers; active/PASV/FTPS upgrades rejected"})
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration input must be a regular file")
	}
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
	c, err := loadConfig(path)
	if err != nil {
		return c, nil, err
	}
	p, err := loadPolicy(c.PolicyFile)
	return c, p, err
}

func loadConfig(path string) (waf.Config, error) {
	b, err := readBounded(path, 64<<10)
	if err != nil {
		return waf.Config{}, err
	}
	c, err := waf.LoadConfig(b)
	if err != nil {
		return c, err
	}
	if c.PolicyFile == "" {
		return c, errors.New("policyFile required")
	}
	if !filepath.IsAbs(c.PolicyFile) {
		c.PolicyFile = filepath.Join(filepath.Dir(path), c.PolicyFile)
	}
	for i := range c.Routes {
		r := &c.Routes[i]
		if !filepath.IsAbs(r.PolicyFile) {
			r.PolicyFile = filepath.Join(filepath.Dir(path), r.PolicyFile)
		}
	}
	return c, nil
}

func validate(ctx context.Context, c *cli.Command) error {
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}
	if err := validateRouteRuntime(c, cfg); err != nil {
		return err
	}
	r, err := newEvaluator(ctx, c, cfg.PolicyFile)
	if err != nil {
		return err
	}
	defer r.Close()
	p := r.Policy()
	if err := validateServeOptions(c, cfg); err != nil {
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
	return policycontrol.Config{Token: os.Getenv("NETCAP_FIREWALL_ADMIN_TOKEN"), Managed: c.Bool("managed"), StateDir: c.String("state-dir"), AllowEffects: c.String("effects-config") != ""}
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
	ctx, runtimeCancel := context.WithCancel(ctx)
	defer runtimeCancel()
	cfg, err := loadConfig(c.String("config"))
	if err != nil {
		return err
	}
	if err := validateServeOptions(c, cfg); err != nil {
		return err
	}
	if err := validateRouteRuntime(c, cfg); err != nil {
		return err
	}
	runtime, err := newEvaluator(ctx, c, cfg.PolicyFile)
	if err != nil {
		return err
	}
	defer runtime.Close()
	f, err := waf.New(cfg, runtime.Policy())
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.SetEvaluator(func(ctx context.Context, p *policy.Compiled, e policy.Event) (policy.Decision, error) {
		return runtime.evaluateContext(ctx, p, e)
	}); err != nil {
		return err
	}
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	reloadCtx, stopReload := context.WithCancel(ctx)
	reloadDone := make(chan struct{})
	defer func() { stopReload(); <-reloadDone }()
	go func() {
		defer close(reloadDone)
		for {
			select {
			case <-reloadCtx.Done():
				return
			case <-reloads:
				if err := f.ReloadTLS(); err != nil {
					fmt.Fprintln(c.Root().ErrWriter, "firewall TLS reload rejected:", err)
					continue
				}
				if len(cfg.Routes) > 0 {
					if err := f.ReloadRoutePolicies(); err != nil {
						fmt.Fprintln(c.Root().ErrWriter, "firewall route reload rejected:", err)
					}
				}
			}
		}
	}()
	if runtime.guard != nil || runtime.nativeState != nil {
		if err = f.SetReadinessCheck(runtime.Ready); err != nil {
			return err
		}
		runtime.startProbes(ctx)
	}
	var dataHandler http.Handler = f
	if c.Bool("websocket") || c.Bool("grpc") {
		dataHandler, err = f.MessageHandler(c.Bool("websocket"), c.Bool("grpc"))
		if err != nil {
			return err
		}
	}
	errs := make(chan error, 4)
	stopAgent, err := runtime.startAgent(ctx, c, f, f.SetDraining, errs)
	if err != nil {
		return err
	}
	defer stopAgent()
	stopMaintenance := startPolicyMaintenance(ctx, f.Policy, c.Root().ErrWriter)
	defer stopMaintenance()
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
	data := &http.Server{Addr: cfg.Listen, Handler: dataHandler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	data.TLSConfig = f.TLSConfig()
	management := &http.Server{Addr: cfg.AdminListen, Handler: firewallui.Wrap(admin, "policy"), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
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
	auditDone := make(chan struct{})
	defer func() { cancel(); <-auditDone }()
	go func() {
		defer close(auditDone)
		if err := f.WriteAudit(auditCtx, c.Root().Writer); err != nil && auditCtx.Err() == nil {
			fmt.Fprintln(c.Root().ErrWriter, "firewall audit sink failed:", err)
		}
	}()
	if c.String("http3-listen") != "" {
		udp, e := net.ListenPacket("udp", c.String("http3-listen"))
		if e != nil {
			return e
		}
		defer udp.Close()
		h3done := make(chan struct{})
		defer func() { runtimeCancel(); <-h3done }()
		go func() {
			defer close(h3done)
			errs <- serveHTTP3(ctx, udp, f.TLSConfigForProtocols("h3"), dataHandler)
		}()
	}
	go func() {
		if cfg.TLSCert != "" {
			errs <- data.ServeTLS(dl, "", "")
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
	runtimeCancel()
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

func validateRouteRuntime(c *cli.Command, cfg waf.Config) error {
	if len(cfg.Routes) == 0 {
		return nil
	}
	if c.Bool("managed") || c.String("fleet-agent-config") != "" || c.String("shared-rate-config") != "" || c.String("policy-state-config") != "" || c.String("effects-config") != "" || c.Bool("websocket") || c.Bool("grpc") || c.String("http3-listen") != "" || os.Getenv("NETCAP_FIREWALL_ADMIN_TOKEN") != "" {
		return errors.New("route bindings currently require local HTTP policies; global management, fleet, effects, shared state and message adapters have no route scope")
	}
	return nil
}

type localTarget struct {
	p atomic.Pointer[policy.Compiled]
}

func (t *localTarget) Policy() *policy.Compiled     { return t.p.Load() }
func (t *localTarget) SetPolicy(p *policy.Compiled) { t.p.Store(p) }

func stdio(ctx context.Context, c *cli.Command) error {
	if c.String("effects-config") != "" || c.String("shared-rate-config") != "" || c.String("policy-state-config") != "" || c.String("fleet-agent-config") != "" || c.Bool("websocket") || c.Bool("grpc") || c.String("http3-listen") != "" {
		return errors.New("stdio authoring does not admit runtime effects, rate guards, fleet or listeners")
	}
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
	runtime, err := newEvaluator(ctx, c, c.String("policy"))
	if err != nil {
		return err
	}
	defer runtime.Close()
	cfg := gateway.Config{Protocol: c.String("protocol"), Listen: c.String("listen"), Upstream: c.String("upstream"), TLSCert: c.String("tls-cert"), TLSKey: c.String("tls-key"), ClientCA: c.String("client-ca"), UpstreamTLS: c.Bool("upstream-tls"), UpstreamServerName: c.String("upstream-server-name"), UpstreamCA: c.String("upstream-ca"), UpstreamCert: c.String("upstream-cert"), UpstreamKey: c.String("upstream-key"), MaxConnections: c.Int("max-connections"), MaxMessageBytes: c.Int("max-message-bytes"), MaxSessionMessages: c.Int("max-session-messages"), MaxStateEntries: c.Int("max-state-entries"), MaxDNSResponseBytes: c.Int("max-dns-response-bytes"), IdleTimeout: c.Duration("idle-timeout"), IOTimeout: c.Duration("io-timeout"), SessionTimeout: c.Duration("session-timeout")}
	for _, v := range c.StringSlice("allow-client") {
		n, err := netip.ParsePrefix(v)
		if err != nil {
			return err
		}
		cfg.AllowedClients = append(cfg.AllowedClients, n)
	}
	g, err := gateway.New(cfg, runtime)
	if err != nil {
		return err
	}
	return runtime.runWithAgent(ctx, c, g.Run)
}

func runEnforcer(ctx context.Context, c *cli.Command) error {
	if err := checkServiceTLS(c); err != nil {
		return err
	}
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
	srv := &http.Server{Addr: c.String("listen"), Handler: firewallui.Wrap(e.Handler(), "leases"), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer l.Close()
	errs := make(chan error, 1)
	go func() {
		if c.String("tls-cert") != "" {
			errs <- srv.ServeTLS(l, c.String("tls-cert"), c.String("tls-key"))
		} else {
			errs <- srv.Serve(l)
		}
	}()
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
