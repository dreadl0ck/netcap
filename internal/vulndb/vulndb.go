/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package vulndb reads and writes netcap.sqlite, the vulnerability and
// exploit database shared by the Go and Rust implementations.
//
// The file format is specified in SCHEMA.md next to this file. Both
// implementations must build identical queries from the same inputs, so the
// query construction below is part of the format, not an implementation
// detail.
package vulndb

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	// Pure Go SQLite with FTS5; keeps CGO_ENABLED=0 and cross builds working.
	_ "modernc.org/sqlite"
)

const (
	// FileName is the database file inside the netcap dbs directory.
	FileName = "netcap.sqlite"

	// Format identifies the file in its meta table.
	Format = "netcap-vulndb"

	// SchemaVersion is bumped on any incompatible table or query change.
	SchemaVersion = 1

	// MaxHits caps the results of one lookup, matching bleve's default
	// search size used by netcap v0.9.x.
	MaxHits = 10
)

const schema = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE nvd (
	id TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL,
	severity TEXT NOT NULL,
	v2_score TEXT NOT NULL,
	access_vector TEXT NOT NULL,
	attack_complexity TEXT NOT NULL,
	confidentiality_impact TEXT NOT NULL,
	integrity_impact TEXT NOT NULL,
	availability_impact TEXT NOT NULL,
	base_score REAL NOT NULL,
	base_severity TEXT NOT NULL
);
CREATE TABLE nvd_versions (
	nvd_rowid INTEGER NOT NULL REFERENCES nvd(rowid),
	version TEXT NOT NULL,
	PRIMARY KEY (version, nvd_rowid)
) WITHOUT ROWID;
CREATE VIRTUAL TABLE nvd_fts USING fts5(description, content='nvd', content_rowid='rowid', tokenize='unicode61');
CREATE TABLE exploits (
	id TEXT NOT NULL UNIQUE,
	file TEXT NOT NULL,
	description TEXT NOT NULL,
	date TEXT NOT NULL,
	author TEXT NOT NULL,
	type TEXT NOT NULL,
	platform TEXT NOT NULL,
	port TEXT NOT NULL
);
CREATE VIRTUAL TABLE exploits_fts USING fts5(description, content='exploits', content_rowid='rowid', tokenize='unicode61');
`

// Vulnerability is one NVD entry.
type Vulnerability struct {
	ID                    string
	Description           string
	Severity              string
	V2Score               string
	AccessVector          string
	AttackComplexity      string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	BaseScore             float64
	BaseSeverity          string
	Versions              []string
}

// Exploit is one Exploit-DB entry. File is relative to the exploitdb folder.
type Exploit struct {
	ID          string
	File        string
	Description string
	Date        string
	Author      string
	Type        string
	Platform    string
	Port        string
}

// Phrase quotes term as an FTS5 phrase, or returns "" when it holds no
// letter or digit (an empty phrase is an FTS5 syntax error).
func Phrase(term string) string {
	term = strings.TrimSpace(term)
	if strings.IndexFunc(term, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) < 0 {
		return ""
	}
	return `"` + strings.ReplaceAll(term, `"`, `""`) + `"`
}

// MatchExpr joins the non-empty phrases of terms with AND.
func MatchExpr(terms ...string) string {
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		if p := Phrase(t); p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, " AND ")
}

// DB is a read-only handle.
type DB struct {
	db   *sql.DB
	path string
}

// ErrSchema reports a file that is not a netcap.sqlite of this schema.
var ErrSchema = errors.New("vulndb: unsupported database schema")

// Open opens path read-only and checks the format and schema version.
func Open(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", "file:"+filepath.ToSlash(abs)+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	d := &DB{db: conn, path: path}
	meta, err := d.Meta()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %s: %v", ErrSchema, path, err)
	}
	if meta["format"] != Format || meta["schema_version"] != fmt.Sprint(SchemaVersion) {
		conn.Close()
		return nil, fmt.Errorf("%w: %s has format=%q schema_version=%q, want %q %d", ErrSchema, path, meta["format"], meta["schema_version"], Format, SchemaVersion)
	}
	return d, nil
}

// Path returns the file the handle was opened from.
func (d *DB) Path() string { return d.path }

// Close releases the handle.
func (d *DB) Close() error { return d.db.Close() }

// Meta returns the meta table.
func (d *DB) Meta() (map[string]string, error) {
	rows, err := d.db.Query(`SELECT key, value FROM meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// Vulnerabilities returns NVD entries whose description contains every
// non-empty phrase of vendor and product and whose version list contains
// version exactly. Without a text term or a version nothing is returned.
func (d *DB) Vulnerabilities(vendor, product, version string) ([]Vulnerability, error) {
	match := MatchExpr(vendor, product)
	version = strings.TrimSpace(version)
	if match == "" || version == "" {
		return nil, nil
	}
	rows, err := d.db.Query(`
SELECT n.id, n.description, n.severity, n.v2_score, n.access_vector, n.attack_complexity,
       n.confidentiality_impact, n.integrity_impact, n.availability_impact, n.base_score, n.base_severity
FROM nvd_fts JOIN nvd n ON n.rowid = nvd_fts.rowid
WHERE nvd_fts MATCH ?1
  AND EXISTS (SELECT 1 FROM nvd_versions v WHERE v.version = ?2 AND v.nvd_rowid = n.rowid)
ORDER BY bm25(nvd_fts), n.id
LIMIT ?3`, match, version, MaxHits)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Vulnerability
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.Description, &v.Severity, &v.V2Score, &v.AccessVector, &v.AttackComplexity,
			&v.ConfidentialityImpact, &v.IntegrityImpact, &v.AvailabilityImpact, &v.BaseScore, &v.BaseSeverity); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Exploits returns Exploit-DB entries whose description contains every
// non-empty phrase of vendor, product and version.
func (d *DB) Exploits(vendor, product, version string) ([]Exploit, error) {
	match := MatchExpr(vendor, product, version)
	if match == "" {
		return nil, nil
	}
	rows, err := d.db.Query(`
SELECT e.id, e.file, e.description, e.date, e.author, e.type, e.platform, e.port
FROM exploits_fts JOIN exploits e ON e.rowid = exploits_fts.rowid
WHERE exploits_fts MATCH ?1
ORDER BY bm25(exploits_fts), e.id
LIMIT ?2`, match, MaxHits)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Exploit
	for rows.Next() {
		var e Exploit
		if err := rows.Scan(&e.ID, &e.File, &e.Description, &e.Date, &e.Author, &e.Type, &e.Platform, &e.Port); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Builder writes a new database to a temporary file and publishes it with a
// rename on Finish, so readers never see a partial file.
type Builder struct {
	db       *sql.DB
	tx       *sql.Tx
	tmp      string
	path     string
	nvd      *sql.Stmt
	versions *sql.Stmt
	exploit  *sql.Stmt
	meta     map[string]string
	counts   [2]int
}

// Create starts a build of path.
func Create(path string) (*Builder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	abs, err := filepath.Abs(tmp)
	if err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", "file:"+filepath.ToSlash(abs)+"?_pragma=journal_mode(OFF)&_pragma=synchronous(OFF)")
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	b := &Builder{db: conn, tmp: tmp, path: path, meta: map[string]string{}}
	if err := b.init(); err != nil {
		b.Abort()
		return nil, err
	}
	return b, nil
}

func (b *Builder) init() (err error) {
	if _, err = b.db.Exec(schema); err != nil {
		return err
	}
	if b.tx, err = b.db.Begin(); err != nil {
		return err
	}
	if b.nvd, err = b.tx.Prepare(`INSERT INTO nvd (id, description, severity, v2_score, access_vector, attack_complexity,
		confidentiality_impact, integrity_impact, availability_impact, base_score, base_severity)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`); err != nil {
		return err
	}
	if b.versions, err = b.tx.Prepare(`INSERT OR IGNORE INTO nvd_versions (nvd_rowid, version) VALUES (?, ?)`); err != nil {
		return err
	}
	b.exploit, err = b.tx.Prepare(`INSERT INTO exploits (id, file, description, date, author, type, platform, port)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`)
	return err
}

// SetMeta records a meta key; format and schema_version are set by Finish.
func (b *Builder) SetMeta(key, value string) { b.meta[key] = value }

// AddVulnerability inserts v; a repeated ID keeps the first entry.
func (b *Builder) AddVulnerability(v Vulnerability) error {
	res, err := b.nvd.Exec(v.ID, v.Description, v.Severity, v.V2Score, v.AccessVector, v.AttackComplexity,
		v.ConfidentialityImpact, v.IntegrityImpact, v.AvailabilityImpact, v.BaseScore, v.BaseSeverity)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for _, ver := range v.Versions {
		if ver = strings.TrimSpace(ver); ver == "" {
			continue
		}
		if _, err := b.versions.Exec(rowid, ver); err != nil {
			return err
		}
	}
	b.counts[0]++
	return nil
}

// AddExploit inserts e; a repeated ID keeps the first entry.
func (b *Builder) AddExploit(e Exploit) error {
	res, err := b.exploit.Exec(e.ID, e.File, e.Description, e.Date, e.Author, e.Type, e.Platform, e.Port)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		b.counts[1]++
	}
	return nil
}

// Counts returns the inserted vulnerability and exploit counts.
func (b *Builder) Counts() (vulnerabilities, exploits int) { return b.counts[0], b.counts[1] }

// Finish indexes, writes meta and atomically replaces path.
func (b *Builder) Finish() error {
	b.meta["format"] = Format
	b.meta["schema_version"] = fmt.Sprint(SchemaVersion)
	b.meta["nvd_count"] = fmt.Sprint(b.counts[0])
	b.meta["exploit_count"] = fmt.Sprint(b.counts[1])
	for k, v := range b.meta {
		if _, err := b.tx.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`, k, v); err != nil {
			b.Abort()
			return err
		}
	}
	for _, s := range []*sql.Stmt{b.nvd, b.versions, b.exploit} {
		s.Close()
	}
	steps := []string{
		`INSERT INTO nvd_fts(nvd_fts) VALUES('rebuild')`,
		`INSERT INTO exploits_fts(exploits_fts) VALUES('rebuild')`,
		`INSERT INTO nvd_fts(nvd_fts) VALUES('optimize')`,
		`INSERT INTO exploits_fts(exploits_fts) VALUES('optimize')`,
	}
	for _, q := range steps {
		if _, err := b.tx.Exec(q); err != nil {
			b.Abort()
			return err
		}
	}
	if err := b.tx.Commit(); err != nil {
		b.Abort()
		return err
	}
	if _, err := b.db.Exec(`VACUUM`); err != nil {
		b.Abort()
		return err
	}
	if err := b.db.Close(); err != nil {
		_ = os.Remove(b.tmp)
		return err
	}
	return os.Rename(b.tmp, b.path)
}

// Abort discards the build.
func (b *Builder) Abort() {
	if b.tx != nil {
		_ = b.tx.Rollback()
	}
	_ = b.db.Close()
	_ = os.Remove(b.tmp)
}
