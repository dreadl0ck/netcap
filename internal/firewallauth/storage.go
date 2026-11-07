package firewallauth

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// OpenPersistent owns a private SQLite ledger for revocations and receipt replay.
// Signing secrets stay in memory. Each service process owns a separate authority.
func OpenPersistent(c Config, dir string, key ed25519.PrivateKey, rules []Protected) (*Authority, *Approvals, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, errors.New("identity state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("identity state directory must be private (0700)")
	}
	path := filepath.Join(dir, "identity.sqlite")
	if info, err = os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, nil, errors.New("identity ledger must be private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	if err = f.Close(); err != nil {
		return nil, nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	r, err := NewSQLRevocations(context.Background(), db)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	c.Revocations = r
	a, err := New(c)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	a.ledger = db
	var approvals *Approvals
	if len(key) > 0 || len(rules) > 0 {
		store, err := NewSQLReplayStore(context.Background(), db)
		if err != nil {
			a.Close()
			return nil, nil, err
		}
		approvals, err = NewApprovals(key, store, rules)
		if err != nil {
			a.Close()
			return nil, nil, err
		}
	}
	return a, approvals, nil
}
func (a *Authority) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.providers {
		p.client.CloseIdleConnections()
	}
	if a.ledger != nil {
		return a.ledger.Close()
	}
	return nil
}

// PinState prevents a retained singleton database being rebound to another
// identity mode or resource scope. Credential rotation does not change the pin.
func PinState(ctx context.Context, db *sql.DB, scope Scope, enabled bool) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS firewall_identity_binding(id INTEGER PRIMARY KEY CHECK(id=1),digest TEXT NOT NULL)`); err != nil {
		return err
	}
	digest := Digest(struct {
		Scope   Scope
		Enabled bool
	}{scope, enabled})
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO firewall_identity_binding VALUES(1,?)`, digest); err != nil {
		return err
	}
	var stored string
	if err := db.QueryRowContext(ctx, `SELECT digest FROM firewall_identity_binding WHERE id=1`).Scan(&stored); err != nil {
		return err
	}
	if stored != digest {
		return errors.New("persisted identity scope/mode cannot be rebound; use a separately provisioned state directory")
	}
	return nil
}
