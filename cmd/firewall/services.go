package firewall

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallfleet"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
	"github.com/dreadl0ck/netcap/internal/firewallui"
	"github.com/dreadl0ck/netcap/internal/policystate"
	"github.com/urfave/cli/v3"
)

type principalFile struct {
	Role     string              `json:"role,omitempty"`
	ID       string              `json:"id"`
	TokenEnv string              `json:"tokenEnv"`
	Scope    firewallstate.Scope `json:"scope"`
}
type serviceFile struct {
	AuthConfig          string          `json:"authConfig"`
	AuditRequired       bool            `json:"auditRequired,omitempty"`
	AuditRetention      string          `json:"auditRetention,omitempty"`
	AuditMaxRecords     int             `json:"auditMaxRecords,omitempty"`
	JobReceiptRetention string          `json:"jobReceiptRetention,omitempty"`
	StateDir            string          `json:"stateDir"`
	TokenEnv            string          `json:"tokenEnv"`
	Identities          []principalFile `json:"identities"`
	Targets             []principalFile `json:"targets"`
	Principals          []principalFile `json:"principals"`
	MaxKeys             int             `json:"maxKeys"`
	AllowEffects        bool            `json:"allowEffects"`
	RollbackOnFailure   bool            `json:"rollbackOnFailure"`
	DatabaseURLEnv      string          `json:"databaseURLEnv"`
	DatabaseNamespace   string          `json:"databaseNamespace"`
}

func (f serviceFile) database() (string, error) {
	if f.DatabaseURLEnv == "" {
		if f.DatabaseNamespace != "" {
			return "", errors.New("databaseNamespace requires databaseURLEnv")
		}
		return "", nil
	}
	if f.StateDir != "" {
		return "", errors.New("stateDir and databaseURLEnv are mutually exclusive")
	}
	if !envName.MatchString(f.DatabaseURLEnv) {
		return "", errors.New("valid databaseURLEnv required")
	}
	raw := os.Getenv(f.DatabaseURLEnv)
	if len(raw) == 0 || len(raw) > 64<<10 || strings.ContainsRune(raw, 0) {
		return "", errors.New("missing or invalid database environment value")
	}
	return raw, nil
}

func fleetConfig(path string) (firewallfleet.Config, error) {
	var f serviceFile
	var cfg firewallfleet.Config
	if err := strictFile(path, &f); err != nil {
		return cfg, err
	}
	var err error
	cfg.DatabaseURL, err = f.database()
	if err != nil {
		return cfg, err
	}
	cfg.DatabaseNamespace = f.DatabaseNamespace
	a, auth, err := loadAuth(f.AuthConfig)
	if err != nil {
		return cfg, err
	}
	cfg.Auth, cfg.Environment, cfg.Origin = a, auth.Scope.Environment, auth.Origin
	cfg.Approvals = auth.approvals
	if len(f.Principals) > 0 || f.MaxKeys != 0 {
		return cfg, errors.New("sharedstate options are invalid for fleet-controller")
	}
	cfg.StateDir = f.StateDir
	cfg.AllowEffects = f.AllowEffects
	cfg.RollbackOnFailure = f.RollbackOnFailure
	cfg.AuditRequired = f.AuditRequired
	cfg.AuditMaxRecords = f.AuditMaxRecords
	if f.JobReceiptRetention != "" {
		cfg.JobReceiptRetention, err = time.ParseDuration(f.JobReceiptRetention)
		if err != nil {
			return cfg, errors.New("invalid jobReceiptRetention duration")
		}
	}
	if f.AuditRetention != "" {
		cfg.AuditRetention, err = time.ParseDuration(f.AuditRetention)
		if err != nil {
			return cfg, errors.New("invalid auditRetention duration")
		}
	}
	if f.TokenEnv != "" {
		var err error
		cfg.Token, err = envToken(f.TokenEnv)
		if err != nil {
			return cfg, err
		}
	}
	for _, p := range f.Identities {
		token, err := envToken(p.TokenEnv)
		if err != nil {
			return cfg, err
		}
		cfg.Identities = append(cfg.Identities, firewallfleet.Identity{ID: p.ID, Token: token, Scope: p.Scope, Role: p.Role})
	}
	for _, p := range f.Targets {
		if p.Role != "" {
			return cfg, errors.New("target enrollment does not accept administrative roles")
		}
		if cfg.Auth != nil && p.TokenEnv == "" {
			cfg.Targets = append(cfg.Targets, firewallfleet.Enrollment{ID: p.ID, Scope: p.Scope})
			continue
		}
		token, err := envToken(p.TokenEnv)
		if err != nil {
			return cfg, err
		}
		cfg.Targets = append(cfg.Targets, firewallfleet.Enrollment{ID: p.ID, Token: token, Scope: p.Scope})
	}
	return cfg, nil
}

func stateConfig(path string) (firewallstate.Config, error) {
	var f serviceFile
	var cfg firewallstate.Config
	if err := strictFile(path, &f); err != nil {
		return cfg, err
	}
	var err error
	cfg.DatabaseURL, err = f.database()
	if err != nil {
		return cfg, err
	}
	cfg.DatabaseNamespace = f.DatabaseNamespace
	if f.TokenEnv != "" || len(f.Identities) > 0 || len(f.Targets) > 0 || f.AllowEffects || f.RollbackOnFailure || f.AuditRequired || f.AuditRetention != "" || f.AuditMaxRecords != 0 || f.JobReceiptRetention != "" {
		return cfg, errors.New("fleet options are invalid for sharedstate")
	}
	cfg.StateDir, cfg.MaxKeys = f.StateDir, f.MaxKeys
	a, auth, err := loadAuth(f.AuthConfig)
	if err != nil {
		return cfg, err
	}
	cfg.Auth, cfg.Environment, cfg.Target, cfg.Origin = a, auth.Scope.Environment, auth.Scope.Target, auth.Origin
	for _, p := range f.Principals {
		token, err := envToken(p.TokenEnv)
		if err != nil {
			return cfg, err
		}
		cfg.Principals = append(cfg.Principals, firewallstate.Principal{ID: p.ID, Token: token, Scope: p.Scope})
	}
	return cfg, nil
}

func serviceFlags() []cli.Flag {
	return []cli.Flag{&cli.StringFlag{Name: "config", Required: true, Usage: "strict JSON bootstrap; tokenEnv and databaseURLEnv reference environment secrets"}, &cli.StringFlag{Name: "listen", Value: "127.0.0.1:9092"}, &cli.StringFlag{Name: "tls-cert"}, &cli.StringFlag{Name: "tls-key"}}
}
func backupFlags() []cli.Flag {
	return []cli.Flag{&cli.StringFlag{Name: "service", Required: true, Usage: "fleet | sharedstate | policy-state"}, &cli.StringFlag{Name: "config", Required: true}, &cli.StringFlag{Name: "output", Required: true, Usage: "absolute snapshot path"}}
}
func restoreFlags() []cli.Flag {
	return []cli.Flag{&cli.StringFlag{Name: "service", Required: true, Usage: "fleet | sharedstate | policy-state"}, &cli.StringFlag{Name: "input", Required: true}, &cli.StringFlag{Name: "state-dir", Required: true}}
}

func checkServiceTLS(c *cli.Command) error {
	cert, key := c.String("tls-cert"), c.String("tls-key")
	if (cert == "") != (key == "") {
		return errors.New("tls-cert and tls-key must be paired")
	}
	if !loopbackAddress(c.String("listen")) && cert == "" {
		return errors.New("non-loopback control service requires TLS")
	}
	if cert != "" {
		_, err := tls.LoadX509KeyPair(cert, key)
		return err
	}
	return nil
}

func serveControl(ctx context.Context, c *cli.Command, h http.Handler) error {
	if err := checkServiceTLS(c); err != nil {
		return err
	}
	l, err := net.Listen("tcp", c.String("listen"))
	if err != nil {
		return err
	}
	defer l.Close()
	s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer s.Close()
	done := make(chan error, 1)
	go func() {
		if c.String("tls-cert") != "" {
			done <- s.ServeTLS(l, c.String("tls-cert"), c.String("tls-key"))
		} else {
			done <- s.Serve(l)
		}
	}()
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = s.Shutdown(shutdown)
		return err
	}
}

func runFleetController(ctx context.Context, c *cli.Command) error {
	if err := checkServiceTLS(c); err != nil {
		return err
	}
	cfg, err := fleetConfig(c.String("config"))
	if cfg.Auth != nil {
		defer cfg.Auth.Close()
	}
	if err != nil {
		return err
	}
	s, err := firewallfleet.New(cfg)
	if err != nil {
		if cfg.DatabaseURL != "" {
			return errors.New("PostgreSQL fleet-controller startup failed; check connectivity, namespace and matching replica bootstrap")
		}
		return err
	}
	defer s.Close()
	maintenanceCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-maintenanceCtx.Done():
				return
			case <-ticker.C:
				if _, err := s.Maintain(maintenanceIdentity(maintenanceCtx, firewallauth.Scope{Tenant: "*", App: "*", Environment: cfg.Environment, Target: "*"}, firewallauth.Rollback)); err != nil && maintenanceCtx.Err() == nil {
					// No request data or credentials enter periodic diagnostics.
					fmt.Fprintln(c.Root().ErrWriter, "fleet maintenance failed")
				}
			}
		}
	}()
	return serveControl(ctx, c, firewallui.Wrap(fleetHealthHandler(s, cfg), "fleet"))
}
func runSharedState(ctx context.Context, c *cli.Command) error {
	if err := checkServiceTLS(c); err != nil {
		return err
	}
	cfg, err := stateConfig(c.String("config"))
	if cfg.Auth != nil {
		defer cfg.Auth.Close()
	}
	if err != nil {
		return err
	}
	s, err := firewallstate.New(cfg)
	if err != nil {
		if cfg.DatabaseURL != "" {
			return errors.New("PostgreSQL sharedstate startup failed; check connectivity, namespace and matching replica bootstrap")
		}
		return err
	}
	defer s.Close()
	return serveControl(ctx, c, s.Handler())
}
func runBackup(ctx context.Context, c *cli.Command) error {
	switch c.String("service") {
	case "policy-state":
		cfg, err := nativeStateConfig(c.String("config"))
		if cfg.Auth != nil {
			defer cfg.Auth.Close()
		}
		if err != nil {
			return err
		}
		s, err := policystate.New(cfg)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.ConsistentBackup(maintenanceIdentity(ctx, firewallauth.Scope{Tenant: "*", App: "*", Environment: cfg.Environment, Target: cfg.Target}, firewallauth.Audit), c.String("output"))
	case "fleet":
		cfg, err := fleetConfig(c.String("config"))
		if cfg.Auth != nil {
			defer cfg.Auth.Close()
		}
		if err != nil {
			return err
		}
		if cfg.DatabaseURL != "" {
			return errors.New("PostgreSQL backup requires native database backup (pg_dump or managed snapshots); restore with PostgreSQL tooling")
		}
		s, err := firewallfleet.New(cfg)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.Backup(maintenanceIdentity(ctx, firewallauth.Scope{Tenant: "*", App: "*", Environment: cfg.Environment, Target: "*"}, firewallauth.Audit), c.String("output"))
	case "sharedstate":
		cfg, err := stateConfig(c.String("config"))
		if cfg.Auth != nil {
			defer cfg.Auth.Close()
		}
		if err != nil {
			return err
		}
		if cfg.DatabaseURL != "" {
			return errors.New("PostgreSQL backup requires native database backup (pg_dump or managed snapshots); restore with PostgreSQL tooling")
		}
		s, err := firewallstate.New(cfg)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.Backup(maintenanceIdentity(ctx, firewallauth.Scope{Tenant: "*", App: "*", Environment: cfg.Environment, Target: cfg.Target}, firewallauth.Audit), c.String("output"))
	default:
		return errors.New("service must be fleet, sharedstate or policy-state")
	}
}
func runRestore(ctx context.Context, c *cli.Command) error {
	if c.String("service") != "fleet" && c.String("service") != "sharedstate" && c.String("service") != "policy-state" {
		return errors.New("service must be fleet, sharedstate or policy-state")
	}
	if c.String("service") == "policy-state" {
		return firewallstate.Restore(ctx, c.String("input"), c.String("state-dir"), "policystate")
	}
	return firewallstate.Restore(ctx, c.String("input"), c.String("state-dir"), c.String("service"))
}

type agentFile struct {
	URL            string              `json:"url"`
	TokenEnv       string              `json:"tokenEnv"`
	TargetID       string              `json:"targetID"`
	Scope          firewallfleet.Scope `json:"scope"`
	StateDir       string              `json:"stateDir"`
	PollInterval   time.Duration       `json:"pollInterval"`
	RequestTimeout time.Duration       `json:"requestTimeout"`
	MaxStale       time.Duration       `json:"maxStale"`
	CA             string              `json:"ca"`
	Cert           string              `json:"cert"`
	Key            string              `json:"key"`
	AllowEffects   *bool               `json:"allowEffects"`
}

func agentConfig(path string, brokerConfigured bool) (firewallfleet.AgentConfig, func(), error) {
	var f agentFile
	var cfg firewallfleet.AgentConfig
	noop := func() {}
	if err := strictFile(path, &f); err != nil {
		return cfg, noop, err
	}
	allowEffects := brokerConfigured
	if f.AllowEffects != nil {
		if *f.AllowEffects && !brokerConfigured {
			return cfg, noop, errors.New("agent allowEffects requires an effects-config broker")
		}
		allowEffects = *f.AllowEffects
	}
	token, err := envToken(f.TokenEnv)
	if err != nil {
		return cfg, noop, err
	}
	if _, err = firewallstate.Endpoint(f.URL); err != nil {
		return cfg, noop, err
	}
	if !firewallstate.ValidID(f.TargetID) || !f.Scope.Valid() || f.StateDir == "" || f.MaxStale < 0 || f.PollInterval < 0 || f.RequestTimeout < 0 || f.RequestTimeout > 10*time.Second {
		return cfg, noop, errors.New("invalid fleet agent identity, state directory or time bounds")
	}
	if f.PollInterval != 0 && (f.PollInterval < 10*time.Millisecond || f.PollInterval > time.Minute) {
		return cfg, noop, errors.New("fleet agent pollInterval must be 10ms..1m")
	}
	tc, err := clientTLS(f.CA, f.Cert, f.Key)
	if err != nil {
		return cfg, noop, err
	}
	tr := &http.Transport{TLSClientConfig: tc, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: 5 * time.Second}
	cfg = firewallfleet.AgentConfig{URL: f.URL, Token: token, TargetID: f.TargetID, Scope: f.Scope, StateDir: f.StateDir, PollInterval: f.PollInterval, RequestTimeout: f.RequestTimeout, MaxStale: f.MaxStale, Transport: tr, AllowEffects: allowEffects}
	return cfg, tr.CloseIdleConnections, nil
}
