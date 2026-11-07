// Package gateway implements bounded explicit application gateways.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/dreadl0ck/netcap/internal/policy"
)

// Evaluator is implemented by policy.Compiled. Implementations must be concurrency safe.
type Evaluator interface {
	Evaluate(policy.Event) (policy.Decision, error)
}

type Config struct {
	Protocol string
	Listen   string
	Upstream string
	// Empty permits loopback clients only, even on a wildcard listener.
	AllowedClients []netip.Prefix
	MaxConnections int
	IdleTimeout    time.Duration
	IOTimeout      time.Duration
	SessionTimeout time.Duration
	// UDP DNS responses are also limited to three times the query length.
	MaxDNSResponseBytes int
	// TLSCert/TLSKey enable implicit TLS; Postgres/MySQL use SSLRequest negotiation.
	TLSCert, TLSKey string
	// UpstreamTLS verifies the pinned destination against this name and CA pool.
	UpstreamTLS                    bool
	UpstreamServerName, UpstreamCA string
	UpstreamCert, UpstreamKey      string
	// ClientCA requires and verifies listener client certificates when set.
	ClientCA           string
	MaxMessageBytes    int
	MaxSessionMessages int
	MaxStateEntries    int
}

type Gateway struct {
	cfg                  Config
	policy               Evaluator
	upstream             string
	serverTLS, originTLS *tls.Config
	slots                chan struct{}
}

func New(cfg Config, evaluator Evaluator) (*Gateway, error) {
	if evaluator == nil {
		return nil, errors.New("gateway: policy is required")
	}
	if p, ok := evaluator.(*policy.Compiled); ok && p == nil {
		return nil, errors.New("gateway: policy is required")
	}
	switch cfg.Protocol {
	case "modbus", "dns", "dns-tcp", "dns-tls", "redis", "postgres", "smtp", "dnp3", "mysql", "smb", "ftp":
	default:
		return nil, errors.New("gateway: unsupported protocol")
	}
	if cfg.Listen == "" {
		ports := map[string]string{"modbus": "1502", "dns": "1053", "dns-tcp": "1053", "dns-tls": "1853", "redis": "16379", "postgres": "15432", "smtp": "1025", "dnp3": "20000", "mysql": "13306", "smb": "1445", "ftp": "1021"}
		cfg.Listen = "127.0.0.1:" + ports[cfg.Protocol]
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 64
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Second
	}
	if cfg.IOTimeout == 0 {
		cfg.IOTimeout = 5 * time.Second
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 5 * time.Minute
	}
	if cfg.MaxDNSResponseBytes == 0 {
		cfg.MaxDNSResponseBytes = 512
		if cfg.Protocol == "dns-tcp" || cfg.Protocol == "dns-tls" {
			cfg.MaxDNSResponseBytes = 65535
		}
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 1 << 20
	}
	if cfg.MaxSessionMessages == 0 {
		cfg.MaxSessionMessages = 10000
	}
	if cfg.MaxStateEntries == 0 {
		cfg.MaxStateEntries = 128
	}
	if cfg.MaxMessageBytes < 512 || cfg.MaxMessageBytes > 16<<20 || cfg.MaxSessionMessages < 1 || cfg.MaxSessionMessages > 1000000 || cfg.MaxStateEntries < 1 || cfg.MaxStateEntries > 4096 {
		return nil, errors.New("gateway: invalid message/session limits")
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") || (cfg.ClientCA != "" && cfg.TLSCert == "") || (cfg.Protocol == "dns-tls" && cfg.TLSCert == "") || (cfg.Protocol == "dns" && cfg.TLSCert != "") {
		return nil, errors.New("gateway: invalid listener TLS configuration")
	}
	if cfg.Protocol == "ftp" && (cfg.TLSCert != "" || cfg.UpstreamTLS) {
		return nil, errors.New("gateway: FTP profile requires plaintext control and owned plaintext data connections")
	}
	if cfg.UpstreamTLS && cfg.UpstreamServerName == "" {
		return nil, errors.New("gateway: upstream TLS requires a verification server name")
	}
	if (cfg.UpstreamCert == "") != (cfg.UpstreamKey == "") || (!cfg.UpstreamTLS && (cfg.UpstreamCert != "" || cfg.UpstreamCA != "" || cfg.UpstreamServerName != "")) {
		return nil, errors.New("gateway: invalid upstream TLS configuration")
	}
	dnsLimit := 4096
	if cfg.Protocol == "dns-tcp" || cfg.Protocol == "dns-tls" {
		dnsLimit = 65535
	}
	if cfg.MaxConnections < 1 || cfg.MaxConnections > 4096 || cfg.IdleTimeout < time.Millisecond || cfg.IdleTimeout > time.Hour || cfg.IOTimeout < time.Millisecond || cfg.IOTimeout > time.Minute || cfg.SessionTimeout < time.Millisecond || cfg.SessionTimeout > 24*time.Hour || cfg.MaxDNSResponseBytes < 512 || cfg.MaxDNSResponseBytes > dnsLimit {
		return nil, errors.New("gateway: invalid resource limits")
	}
	cfg.AllowedClients = append([]netip.Prefix(nil), cfg.AllowedClients...)
	for _, p := range cfg.AllowedClients {
		if !p.IsValid() {
			return nil, errors.New("gateway: invalid client prefix")
		}
	}
	// Resolve once, so a hostname cannot change destinations between requests.
	a, err := net.ResolveTCPAddr("tcp", cfg.Upstream)
	if err != nil || a == nil || a.Port == 0 || a.IP == nil || a.IP.IsUnspecified() || a.IP.IsMulticast() {
		return nil, errors.New("gateway: upstream must resolve to a fixed unicast host:port")
	}
	g := &Gateway{cfg: cfg, policy: evaluator, upstream: a.String(), slots: make(chan struct{}, cfg.MaxConnections)}
	if g.serverTLS, err = g.listenerTLS(); err != nil {
		return nil, err
	}
	if g.originTLS, err = g.upstreamTLS(); err != nil {
		return nil, err
	}
	return g, nil
}

func Run(ctx context.Context, cfg Config, compiled *policy.Compiled) error {
	if compiled == nil {
		return errors.New("gateway: policy is required")
	}
	g, err := New(cfg, compiled)
	if err != nil {
		return err
	}
	return g.Run(ctx)
}

func (g *Gateway) Run(ctx context.Context) error {
	if g.cfg.Protocol == "dns" {
		pc, err := net.ListenPacket("udp", g.cfg.Listen)
		if err != nil {
			return err
		}
		return g.ServePacket(ctx, pc)
	}
	l, err := net.Listen("tcp", g.cfg.Listen)
	if err != nil {
		return err
	}
	return g.Serve(ctx, l)
}

func (g *Gateway) clientAllowed(addr net.Addr) (string, bool) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if len(g.cfg.AllowedClients) == 0 {
		return ip.String(), ip.IsLoopback()
	}
	for _, p := range g.cfg.AllowedClients {
		if p.Contains(ip) {
			return ip.String(), true
		}
	}
	return ip.String(), false
}

func (g *Gateway) allowed(e policy.Event) bool {
	d, err := g.policy.Evaluate(e)
	return err == nil && (d.Verdict == "allow" || d.Verdict == "would-deny")
}

func deadline(ctx context.Context, timeout time.Duration) time.Time {
	d := time.Now().Add(timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(d) {
		return end
	}
	return d
}

func protocolError(protocol string) error {
	return fmt.Errorf("gateway: listener incompatible with %s", protocol)
}
