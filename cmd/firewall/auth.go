package firewall

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strings"

	"github.com/dreadl0ck/netcap/internal/firewallauth"
	"github.com/dreadl0ck/netcap/internal/firewallstate"
)

type authFile struct {
	DatabaseURLEnv    string                   `json:"databaseURLEnv"`
	DatabaseNamespace string                   `json:"databaseNamespace"`
	StateDir          string                   `json:"stateDir"`
	ApprovalKeyEnv    string                   `json:"approvalKeyEnv"`
	Protected         []firewallauth.Protected `json:"protected"`
	approvals         *firewallauth.Approvals
	Static            []struct {
		TokenEnv  string                 `json:"tokenEnv"`
		Principal firewallauth.Principal `json:"principal"`
	} `json:"static"`
	Providers []firewallauth.Provider `json:"providers"`
	Scope     firewallauth.Scope      `json:"scope"`
	Origin    string                  `json:"origin"`
	Stdio     *firewallauth.Principal `json:"stdio"`
}

// Only the process-owned maintenance loop receives this bootstrap identity.
func maintenanceIdentity(ctx context.Context, scope firewallauth.Scope, action firewallauth.Action) context.Context {
	return firewallauth.WithPrincipal(ctx, firewallauth.Principal{ID: "local-maintenance", Grants: []firewallauth.Grant{{Scope: scope, Actions: []firewallauth.Action{action}}}})
}

func loadAuth(path string) (*firewallauth.Authority, authFile, error) {
	var f authFile
	if path == "" {
		return nil, f, nil
	}
	if err := strictFile(path, &f); err != nil {
		return nil, f, err
	}
	if f.DatabaseNamespace != "" && f.DatabaseURLEnv == "" {
		return nil, f, errors.New("databaseNamespace requires databaseURLEnv")
	}
	if f.Origin != "" {
		u, err := url.Parse(f.Origin)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(f.Origin, "*") {
			return nil, f, errors.New("origin must be an exact HTTP(S) origin without path or wildcard")
		}
	}
	if f.Stdio != nil {
		if _, err := firewallauth.New(firewallauth.Config{Static: []firewallauth.Static{{Token: "validate-stdio-identity-only", Principal: *f.Stdio}}}); err != nil {
			return nil, f, errors.New("invalid stdio grants")
		}
	}
	c := firewallauth.Config{Providers: f.Providers}
	for _, s := range f.Static {
		token, err := envToken(s.TokenEnv)
		if err != nil {
			return nil, f, err
		}
		c.Static = append(c.Static, firewallauth.Static{Token: token, Principal: s.Principal})
	}
	if f.StateDir != "" || f.DatabaseURLEnv != "" {
		var key []byte
		if f.ApprovalKeyEnv != "" {
			if !envName.MatchString(f.ApprovalKeyEnv) {
				return nil, f, errors.New("invalid approvalKeyEnv")
			}
			var err error
			key, err = base64.StdEncoding.DecodeString(os.Getenv(f.ApprovalKeyEnv))
			if err != nil || len(key) != ed25519.PrivateKeySize {
				return nil, f, errors.New("approval signing key must be base64 Ed25519 private key")
			}
		}
		var a *firewallauth.Authority
		var approvals *firewallauth.Approvals
		var err error
		if f.DatabaseURLEnv != "" {
			if f.StateDir != "" || !envName.MatchString(f.DatabaseURLEnv) || f.DatabaseNamespace == "" {
				return nil, f, errors.New("shared auth requires databaseURLEnv and dedicated databaseNamespace, without stateDir")
			}
			db, e := firewallstate.OpenPostgres(context.Background(), os.Getenv(f.DatabaseURLEnv), f.DatabaseNamespace)
			if e != nil {
				return nil, f, e
			}
			a, approvals, err = firewallauth.OpenShared(context.Background(), c, db, key, f.Protected)
			if err != nil {
				db.Close()
			}
		} else {
			a, approvals, err = firewallauth.OpenPersistent(c, f.StateDir, key, f.Protected)
		}
		f.approvals = approvals
		return a, f, err
	}
	if f.ApprovalKeyEnv != "" || len(f.Protected) > 0 {
		return nil, f, errors.New("approval protection requires durable identity stateDir")
	}
	a, err := firewallauth.New(c)
	return a, f, err
}
