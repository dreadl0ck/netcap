package firewallauth

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"
)

// SharedDatabase is implemented by firewallstate.Database; the callback runs
// under its transaction-scoped namespace lock, including reads and capacity checks.
type SharedDatabase interface {
	AuthNamespace() string
	AuthTransaction(context.Context, func(SQLTransaction) error) error
	Bootstrap(context.Context, string, []string) error
	Close() error
}
type SQLTransaction interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	Clock(context.Context, int64) (int64, error)
}
type sharedLedger struct{ db SharedDatabase }

func OpenShared(ctx context.Context, c Config, db SharedDatabase, key ed25519.PrivateKey, rules []Protected) (*Authority, *Approvals, error) {
	a, err := New(c)
	if err != nil {
		return nil, nil, err
	}
	l := &sharedLedger{db}
	var approvals *Approvals
	if len(key) > 0 || len(rules) > 0 {
		approvals, err = NewApprovals(key, l, rules)
		if err != nil {
			a.Close()
			return nil, nil, err
		}
	}
	// Canonicalize policy sets; secrets and JWKS cache contents never enter SQL.
	normalize := func(p Principal) Principal {
		p = clone(p)
		p.Grants = append([]Grant{}, p.Grants...)
		for i := range p.Grants {
			p.Grants[i].Actions = append([]Action{}, p.Grants[i].Actions...)
			slices.Sort(p.Grants[i].Actions)
			p.Grants[i].Actions = slices.Compact(p.Grants[i].Actions)
		}
		slices.SortFunc(p.Grants, func(x, y Grant) int { return strings.Compare(Digest(x), Digest(y)) })
		p.Grants = slices.CompactFunc(p.Grants, func(x, y Grant) bool { return Digest(x) == Digest(y) })
		return p
	}
	statics := make([]Principal, 0, len(a.static))
	for _, s := range a.static {
		statics = append(statics, normalize(s.Principal))
	}
	slices.SortFunc(statics, func(x, y Principal) int { return strings.Compare(Digest(x), Digest(y)) })
	statics = slices.CompactFunc(statics, func(x, y Principal) bool { return Digest(x) == Digest(y) })
	providers := make([]Provider, 0, len(a.providers))
	for _, p := range a.providers {
		v := p.cfg
		v.Subjects = make(map[string]Principal, len(p.cfg.Subjects))
		for sub, principal := range p.cfg.Subjects {
			v.Subjects[sub] = normalize(principal)
		}
		v.RevokedIDs = append([]string{}, v.RevokedIDs...)
		slices.Sort(v.RevokedIDs)
		v.RevokedIDs = slices.Compact(v.RevokedIDs)
		providers = append(providers, v)
	}
	slices.SortFunc(providers, func(x, y Provider) int { return strings.Compare(Digest(x), Digest(y)) })
	protection := append([]Protected{}, rules...)
	slices.SortFunc(protection, func(x, y Protected) int { return strings.Compare(Digest(x), Digest(y)) })
	protection = slices.Compact(protection)
	var public []byte
	if len(key) == ed25519.PrivateKeySize {
		public = key.Public().(ed25519.PublicKey)
	}
	fp := Digest(struct {
		Version   int
		Static    []Principal
		Providers []Provider
		Rules     []Protected
		Public    []byte
	}{1, statics, providers, protection, public})
	if err = db.Bootstrap(ctx, fp, []string{
		`CREATE TABLE IF NOT EXISTS firewall_credential_revocations(digest TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS firewall_approval_replay(id TEXT PRIMARY KEY,expires BIGINT NOT NULL)`,
	}); err != nil {
		a.Close()
		return nil, nil, err
	}
	a.revocations, a.shared = l, db
	a.policyFingerprint = Digest(struct{ Policy, Namespace string }{fp, db.AuthNamespace()})
	return a, approvals, nil
}
func (a *Authority) Shared() bool { return a != nil && a.shared != nil }

func (a *Authority) PolicyFingerprint() string {
	if a == nil {
		return ""
	}
	return a.policyFingerprint
}
func (l *sharedLedger) Revoked(ctx context.Context, digest string) (revoked bool, err error) {
	err = l.db.AuthTransaction(ctx, func(tx SQLTransaction) error {
		var n int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM firewall_credential_revocations WHERE digest=?`, digest).Scan(&n)
		revoked = n != 0
		return err
	})
	return
}
func (l *sharedLedger) Revoke(ctx context.Context, digest string) error {
	if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
		return errors.New("invalid credential fingerprint")
	}
	return l.db.AuthTransaction(ctx, func(tx SQLTransaction) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM firewall_credential_revocations`).Scan(&n); err != nil {
			return err
		}
		if n >= 4096 {
			return errors.New("credential revocation capacity exhausted")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO firewall_credential_revocations VALUES(?) ON CONFLICT(digest) DO NOTHING`, strings.ToLower(digest))
		return err
	})
}
func (l *sharedLedger) Consume(ctx context.Context, id string, expiry time.Time) error {
	return l.db.AuthTransaction(ctx, func(tx SQLTransaction) error {
		stamp, err := tx.Clock(ctx, time.Now().UnixNano())
		if err != nil {
			return err
		}
		now := time.Unix(0, stamp)
		if !expiry.After(now) {
			return ErrForbidden
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM firewall_approval_replay WHERE expires < ?`, now.Add(-time.Minute).Unix()); err != nil {
			return err
		}
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM firewall_approval_replay`).Scan(&n); err != nil {
			return err
		}
		if n >= 4096 {
			return errors.New("approval replay capacity exhausted")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO firewall_approval_replay VALUES(?,?)`, id, expiry.Unix())
		if err != nil {
			return ErrForbidden
		}
		return nil
	})
}
