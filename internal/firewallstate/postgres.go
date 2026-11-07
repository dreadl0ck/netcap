package firewallstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

var postgresNamespace = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

// OpenPostgres opens an independent connection pool. Namespace is a dedicated
// schema and serialization domain, shared by all replicas of one service.
// Database URLs are bootstrap secrets and are never included in returned errors.
func OpenPostgres(ctx context.Context, rawURL, namespace string) (*Database, error) {
	if !postgresNamespace.MatchString(namespace) || namespace == "public" || namespace == "information_schema" || strings.HasPrefix(namespace, "pg_") {
		return nil, errors.New("invalid PostgreSQL namespace")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u == nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.Hostname() == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" {
		return nil, errors.New("invalid PostgreSQL database URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL database URL")
	}
	for _, values := range query {
		if len(values) != 1 {
			return nil, errors.New("duplicate PostgreSQL URL parameter")
		}
	}
	if strings.Contains(u.Hostname(), ",") {
		return nil, errors.New("PostgreSQL URL requires one authoritative endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := ip != nil && ip.IsLoopback()
	if !loopback && query.Get("sslmode") != "verify-full" {
		return nil, errors.New("nonloopback PostgreSQL requires sslmode=verify-full")
	}
	// Disallow alternative hosts/options that could bypass the URL's TLS check or
	// redirect a connection into a different schema/coordination domain.
	for key := range query {
		switch key {
		case "sslmode", "sslrootcert", "sslcert", "sslkey", "sslpassword", "sslsni", "channel_binding", "connect_timeout":
		default:
			return nil, errors.New("unsupported PostgreSQL URL parameter")
		}
	}
	query.Set("connect_timeout", "5")
	query.Set("search_path", `"`+namespace+`"`)
	query.Set("statement_timeout", "5000")
	query.Set("lock_timeout", "5000")
	query.Set("idle_in_transaction_session_timeout", "5000")
	query.Set("synchronous_commit", "on")
	u.RawQuery = query.Encode()
	connection, err := pq.NewConfig(u.String())
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	// PGOPTIONS/PGHOSTADDR and service files must not bypass the bootstrap
	// endpoint, namespace, durability, or deadline configuration.
	connection.Host = u.Hostname()
	connection.Hostaddr = netip.Addr{}
	connection.Multi = nil
	port := 5432
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid PostgreSQL port")
		}
	}
	connection.Port = uint16(port)
	connection.Database = strings.TrimPrefix(u.Path, "/")
	connection.Options = ""
	connection.Service = ""
	connection.ServiceFile = ""
	connection.ConnectTimeout = 5 * time.Second
	connection.TargetSessionAttrs = pq.TargetSessionAttrsReadWrite
	connection.SSLMode = pq.SSLMode(query.Get("sslmode"))
	if connection.SSLMode == "" {
		connection.SSLMode = pq.SSLModeRequire
	}
	connection.Runtime = map[string]string{"search_path": `"` + namespace + `"`, "statement_timeout": "5000", "lock_timeout": "5000", "idle_in_transaction_session_timeout": "5000", "synchronous_commit": "on", "standard_conforming_strings": "on"}
	connector, err := pq.NewConnectorConfig(connection)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errors.New("PostgreSQL connection unavailable")
	}
	hash := sha256.Sum256([]byte("netcap-firewall:" + namespace))
	d := &Database{DB: db, postgres: true, namespace: namespace, lockID: int64(binary.BigEndian.Uint64(hash[:8]))}
	tx, err := d.Begin(ctx)
	if err != nil {
		_ = d.Close()
		return nil, errors.New("PostgreSQL coordination unavailable")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS "`+namespace+`"`); err != nil {
		_ = tx.Rollback()
		_ = d.Close()
		return nil, errors.New("PostgreSQL namespace unavailable")
	}
	if err = tx.Commit(); err != nil {
		_ = d.Close()
		return nil, errors.New("PostgreSQL namespace commit failed")
	}
	return d, nil
}

func (d *Database) IsPostgres() bool { return d.postgres }
func (d *Database) Coordination() string {
	if d.postgres {
		return "PostgreSQL namespace transaction serialization; active-active replicas; per-target generations; no globally atomic activation"
	}
	return "singleton SQLite; per-target generations; no global atomic activation"
}

// Transaction uses READ COMMITTED plus a transaction-scoped exclusive advisory
// lock. Reads happen AFTER lock acquisition and see the preceding writer's commit.
// No ambiguous commit is retried, and no process-local lock provides PG safety.
type Transaction struct {
	*sql.Tx
	database   *Database
	connection *sql.Conn
}

func (d *Database) Begin(ctx context.Context) (*Transaction, error) {
	var options *sql.TxOptions
	if d.postgres {
		options = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	var tx *sql.Tx
	var connection *sql.Conn
	var err error
	if d.postgres {
		connection, err = d.DB.Conn(ctx)
		if err == nil {
			tx, err = connection.BeginTx(ctx, options)
		}
	} else {
		tx, err = d.DB.BeginTx(ctx, options)
	}
	if err != nil {
		if connection != nil {
			discardPostgresConnection(connection)
			_ = connection.Close()
		}
		return nil, err
	}
	t := &Transaction{Tx: tx, database: d, connection: connection}
	if d.postgres {
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, d.lockID); err != nil {
			_ = t.Rollback()
			return nil, err
		}
		if d.fingerprint != "" {
			if err = d.checkBootstrap(ctx, t); err != nil {
				_ = tx.Rollback()
				discardPostgresConnection(connection)
				_ = connection.Close()
				return nil, err
			}
		}
	}
	return t, nil
}

func discardPostgresConnection(connection *sql.Conn) {
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
}
func (t *Transaction) Commit() error {
	err := t.Tx.Commit()
	if t.connection != nil {
		if err != nil {
			discardPostgresConnection(t.connection)
		}
		_ = t.connection.Close()
	}
	return err
}
func (t *Transaction) Rollback() error {
	err := t.Tx.Rollback()
	if t.connection != nil {
		_ = t.connection.Close()
	}
	return err
}
func (t *Transaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, t.database.Rebind(query), args...)
}
func (t *Transaction) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, t.database.Rebind(query), args...)
}
func (t *Transaction) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, t.database.Rebind(query), args...)
}

// Bootstrap atomically creates the service schema and pins its canonical hashed
// bootstrap configuration. Mismatched replicas fail before touching service state.
func (d *Database) Bootstrap(ctx context.Context, fingerprint string, statements []string) error {
	if !d.postgres || !validHash(fingerprint) {
		return errors.New("invalid PostgreSQL bootstrap")
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS bootstrap(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,fingerprint TEXT NOT NULL)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO bootstrap VALUES(1,1,?) ON CONFLICT(id) DO NOTHING`, fingerprint); err != nil {
		return err
	}
	var version int
	var persisted string
	if err = tx.QueryRowContext(ctx, `SELECT version,fingerprint FROM bootstrap WHERE id=1`).Scan(&version, &persisted); err != nil {
		return err
	}
	if version != 1 || persisted != fingerprint {
		return errors.New("PostgreSQL bootstrap fingerprint mismatch; replicas must use identical scoped configuration")
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	d.fingerprint = fingerprint
	return nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (d *Database) checkBootstrap(ctx context.Context, q rowQuerier) error {
	var version int
	var fingerprint string
	var recovery bool
	var readOnly string
	if err := q.QueryRowContext(ctx, `SELECT version,fingerprint,pg_is_in_recovery(),current_setting('transaction_read_only') FROM bootstrap WHERE id=1`).Scan(&version, &fingerprint, &recovery, &readOnly); err != nil {
		return err
	}
	if recovery || readOnly != "off" {
		return errors.New("PostgreSQL authoritative writer unavailable")
	}
	if version != 1 || fingerprint != d.fingerprint {
		return errors.New("PostgreSQL bootstrap fingerprint mismatch")
	}
	return nil
}
func (d *Database) CheckBootstrap(ctx context.Context) error {
	if !d.postgres {
		return nil
	}
	connection, err := d.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err = d.checkBootstrap(ctx, connection); err != nil {
		discardPostgresConnection(connection)
	}
	return err
}

// PostgreSQL owns counter time; the caller's process clock is not authoritative.
func (t *Transaction) Clock(ctx context.Context, fallback int64) (int64, error) {
	if !t.database.postgres {
		return fallback, nil
	}
	var stamp int64
	err := t.QueryRowContext(ctx, `SELECT (extract(epoch FROM clock_timestamp())*1000000000)::bigint`).Scan(&stamp)
	return stamp, err
}

// Rebind is for this package's SQL constants, not arbitrary PostgreSQL operators.
// Quoted strings/identifiers, comments and dollar-quoted bodies are preserved.
func (d *Database) Rebind(query string) string {
	if !d.postgres {
		return query
	}
	var out strings.Builder
	parameter := 0
	for i := 0; i < len(query); {
		start := i
		switch {
		case query[i] == '\'' || query[i] == '"':
			quote := query[i]
			escaped := quote == '\'' && i > 0 && (query[i-1] == 'E' || query[i-1] == 'e')
			i++
			for i < len(query) {
				if query[i] == '\\' && escaped && i+1 < len(query) {
					i += 2
					continue
				}
				if query[i] == quote {
					i++
					if i < len(query) && query[i] == quote {
						i++
						continue
					}
					break
				}
				i++
			}
		case strings.HasPrefix(query[i:], "--"):
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case strings.HasPrefix(query[i:], "/*"):
			i += 2
			depth := 1
			for i < len(query) && depth > 0 {
				if strings.HasPrefix(query[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(query[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
		case query[i] == '$':
			end := i + 1
			for end < len(query) && (query[end] >= 'a' && query[end] <= 'z' || query[end] >= 'A' && query[end] <= 'Z' || query[end] == '_' || query[end] >= '0' && query[end] <= '9' && end > i+1) {
				end++
			}
			if end < len(query) && query[end] == '$' {
				tag := query[i : end+1]
				if close := strings.Index(query[end+1:], tag); close >= 0 {
					i = end + 1 + close + len(tag)
				} else {
					i = len(query)
				}
			} else {
				i++
			}
		case query[i] == '?':
			parameter++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(parameter))
			i++
			continue
		default:
			i++
		}
		out.WriteString(query[start:i])
	}
	return out.String()
}
