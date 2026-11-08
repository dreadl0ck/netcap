package firewall

import (
	"context"
	"net/http"
	"time"

	"github.com/dreadl0ck/netcap/internal/policystate"
	"github.com/urfave/cli/v3"
)

type policyStateFile struct {
	AuthConfig        string          `json:"authConfig"`
	StateDir          string          `json:"stateDir"`
	DatabaseURLEnv    string          `json:"databaseURLEnv"`
	DatabaseNamespace string          `json:"databaseNamespace"`
	Principals        []principalFile `json:"principals"`
	AllowEffects      bool            `json:"allowEffects"`
	MaxRevisions      int             `json:"maxRevisions"`
	MaxStateBytes     int             `json:"maxStateBytes"`
}

func nativeStateConfig(path string) (policystate.Config, error) {
	var f policyStateFile
	var cfg policystate.Config
	if err := strictFile(path, &f); err != nil {
		return cfg, err
	}
	raw, err := (serviceFile{StateDir: f.StateDir, DatabaseURLEnv: f.DatabaseURLEnv, DatabaseNamespace: f.DatabaseNamespace}).database()
	if err != nil {
		return cfg, err
	}
	cfg = policystate.Config{StateDir: f.StateDir, DatabaseURL: raw, DatabaseNamespace: f.DatabaseNamespace, AllowEffects: f.AllowEffects, MaxRevisions: f.MaxRevisions, MaxStateBytes: f.MaxStateBytes}
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
		cfg.Principals = append(cfg.Principals, policystate.Principal{ID: p.ID, Token: token, Scope: p.Scope})
	}
	return cfg, nil
}

func runPolicyState(ctx context.Context, c *cli.Command) error {
	if err := checkServiceTLS(c); err != nil {
		return err
	}
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
	return serveControl(ctx, c, s.Handler())
}

type nativeClientFile struct {
	URL            string        `json:"url"`
	TokenEnv       string        `json:"tokenEnv"`
	CA             string        `json:"ca"`
	Cert           string        `json:"cert"`
	Key            string        `json:"key"`
	RequestTimeout time.Duration `json:"requestTimeout"`
}

func nativeStateClient(path string) (*policystate.Client, error) {
	var f nativeClientFile
	if err := strictFile(path, &f); err != nil {
		return nil, err
	}
	token, err := envToken(f.TokenEnv)
	if err != nil {
		return nil, err
	}
	tc, err := clientTLS(f.CA, f.Cert, f.Key)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: tc, MaxConnsPerHost: 8, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: 5 * time.Second}
	client, err := policystate.NewClient(policystate.ClientConfig{URL: f.URL, Token: token, Timeout: f.RequestTimeout, Transport: tr})
	if err != nil {
		tr.CloseIdleConnections()
	}
	return client, err
}
