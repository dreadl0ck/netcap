// Package firewallstate provides authoritative, scoped shared counters. SQLite
// is a fenced singleton; optional PostgreSQL coordinates active-active replicas.
package firewallstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// Database holds a separate SQLite lifetime lock or a PostgreSQL connection pool.
// Stop listeners and users before Close. Copying a SQLite database does not fence
// its old host; PostgreSQL writers must use Begin's namespace transaction lock.
type Database struct {
	DB           *sql.DB
	owner        *sql.DB
	postgres     bool
	namespace    string
	authEndpoint string
	lockID       int64
	fingerprint  string
}

func PrivateDir(dir string) error {
	if dir == "" {
		return errors.New("state directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	i, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private (0700), without symlink")
	}
	return nil
}

func PrivateFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		return f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return errors.New("state file must be private regular file (0600)")
	}
	return nil
}

func sqliteURL(path string) string {
	abs, _ := filepath.Abs(path)
	return (&url.URL{Scheme: "file", Path: abs}).String()
}

func OpenDatabase(dir, name string) (*Database, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("invalid database name")
	}
	if err := PrivateDir(dir); err != nil {
		return nil, err
	}
	d := &Database{}
	fail := func(err error) (*Database, error) { _ = d.Close(); return nil, err }
	lock := filepath.Join(dir, name+".lock")
	if err := PrivateFile(lock); err != nil {
		return fail(err)
	}
	var err error
	d.owner, err = sql.Open("sqlite", sqliteURL(lock))
	if err != nil {
		return fail(err)
	}
	d.owner.SetMaxOpenConns(1)
	if _, err = d.owner.Exec(`PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS fence (id INTEGER);`); err != nil {
		return fail(fmt.Errorf("state directory already owned: %w", err))
	}
	path := filepath.Join(dir, name+".sqlite")
	if err = PrivateFile(path); err != nil {
		return fail(err)
	}
	d.DB, err = sql.Open("sqlite", sqliteURL(path))
	if err != nil {
		return fail(err)
	}
	d.DB.SetMaxOpenConns(1)
	if _, err = d.DB.Exec(`PRAGMA busy_timeout=1000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;`); err != nil {
		return fail(err)
	}
	return d, nil
}

func (d *Database) Close() error {
	var err error
	if d.DB != nil {
		err = d.DB.Close()
	}
	if d.owner != nil {
		err = errors.Join(err, d.owner.Close())
	}
	return err
}

// Backup uses a consistent SQLite snapshot. Destination is an operator-supplied
// local path, never bundle input, and must not exist. Protect the backup as secrets.
func (d *Database) Backup(ctx context.Context, destination string) error {
	if d.postgres {
		return errors.New("PostgreSQL backup requires operator-managed pg_dump or native database backup")
	}
	if !filepath.IsAbs(destination) {
		return errors.New("absolute backup destination required")
	}
	if err := PrivateDir(filepath.Dir(destination)); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("backup destination already exists or is inaccessible")
	}
	// VACUUM INTO cannot target a pre-created file; private parent protects creation.
	_, err := d.DB.ExecContext(ctx, `VACUUM INTO '`+strings.ReplaceAll(destination, "'", "''")+`'`)
	if err != nil {
		return err
	}
	return os.Chmod(destination, 0600)
}

// Restore is offline: acquires the destination singleton lock and refuses an
// existing database. New/validation must succeed before exposing a restored service.
func Restore(ctx context.Context, backup, dir, name string) error {
	if _, err := os.Lstat(backup); err != nil {
		return err
	}
	if err := PrivateFile(backup); err != nil {
		return err
	}
	src, err := sql.Open("sqlite", sqliteURL(backup)+"?mode=ro")
	if err != nil {
		return err
	}
	defer src.Close()
	var integrity string
	if err = src.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("invalid backup integrity")
	}
	if err = PrivateDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name+".sqlite")
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("restore destination exists")
	}
	d, err := OpenDatabase(dir, name)
	if err != nil {
		return err
	}
	defer d.Close()
	// Remove only the new empty file while ownership remains held.
	if err = d.DB.Close(); err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	if err = dBackupInto(ctx, src, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func dBackupInto(ctx context.Context, db *sql.DB, path string) error {
	_, err := db.ExecContext(ctx, `VACUUM INTO '`+strings.ReplaceAll(path, "'", "''")+`'`)
	return err
}
