// Package delivery provides opt-in, at-least-once webhook delivery. Receivers
// must deduplicate Idempotency-Key; a crash after acceptance can repeat a POST.
package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dreadl0ck/netcap/types"
	_ "modernc.org/sqlite"
)

var ErrFull = errors.New("alert outbox capacity reached (including idempotency receipts)")

const MaxEntries = 10000

// Notice intentionally excludes raw records, expressions, notes, descriptions,
// tags and authentication material. Scope is supplied by the capture owner.
type Notice struct {
	Version      string `json:"version"`
	Scope        string `json:"scope"`
	Timestamp    int64  `json:"timestamp,string"`
	Rule         string `json:"rule"`
	Severity     string `json:"severity"`
	RecordType   string `json:"recordType"`
	RuleDigest   string `json:"ruleDigest"`
	RecordDigest string `json:"recordDigest"`
	SrcIP        string `json:"srcIP"`
	DstIP        string `json:"dstIP"`
}

type Outbox struct {
	db       *sql.DB
	endpoint string
	client   *http.Client
	mu       sync.Mutex
}

// Open pins a private database to one destination. Credentials belong in the
// runtime request header, never the URL or persisted queue. No worker is spawned.
func Open(directory, endpoint string) (*Outbox, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("webhook requires an HTTP(S) URL without credentials, query or fragment")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	path, err := filepath.Abs(filepath.Join(directory, "alert-outbox.sqlite"))
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String() + "?_pragma=busy_timeout(5000)&_pragma=synchronous(FULL)&_pragma=max_page_count(16384)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ok := false
	defer func() {
		if !ok {
			_ = db.Close()
		}
	}()
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS destination (singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS notices (id TEXT PRIMARY KEY, payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, due INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'pending', status INTEGER NOT NULL DEFAULT 0);
	CREATE INDEX IF NOT EXISTS due_notices ON notices(state,due,id);`)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(endpoint))
	want := hex.EncodeToString(digest[:])
	if _, err = db.Exec(`INSERT OR IGNORE INTO destination VALUES(1,?)`, want); err != nil {
		return nil, err
	}
	var got string
	if err = db.QueryRow(`SELECT digest FROM destination WHERE singleton=1`).Scan(&got); err != nil {
		return nil, err
	}
	if got != want {
		return nil, errors.New("outbox destination differs; use a separate outbox")
	}
	ok = true
	return &Outbox{db: db, endpoint: endpoint, client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Enqueue commits before returning. Identical semantic notices reuse one durable
// receipt even after delivery/restart. Full queues fail rather than lose evidence.
func (o *Outbox) Enqueue(scope string, a *types.Alert) (string, error) {
	if a == nil || scope == "" || len(scope) > 256 || len(a.RuleName) > 256 || len(a.RecordType) > 64 || len(a.Severity) > 32 || len(a.RuleDigest) > 128 || len(a.MatchedRecordSHA256) > 128 || len(a.SrcIP) > 128 || len(a.DstIP) > 128 {
		return "", errors.New("invalid or oversized alert notice")
	}
	n := Notice{Version: "netcap-alert-notice/v1", Scope: scope, Timestamp: a.Timestamp, Rule: a.RuleName, Severity: a.Severity, RecordType: a.RecordType, RuleDigest: a.RuleDigest, RecordDigest: a.MatchedRecordSHA256}
	n.SrcIP, n.DstIP = a.SrcIP, a.DstIP
	if n.RecordDigest == "" && a.MatchedRecord != "" {
		if len(a.MatchedRecord) > 16<<20 {
			return "", errors.New("alert record exceeds digest limit")
		}
		hash := sha256.Sum256([]byte(a.MatchedRecord))
		n.RecordDigest = hex.EncodeToString(hash[:])
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return "", err
	}
	if len(payload) > 4096 {
		return "", errors.New("alert notice exceeds 4096 bytes")
	}
	digest := sha256.Sum256(payload)
	id := hex.EncodeToString(digest[:])
	o.mu.Lock()
	defer o.mu.Unlock()
	tx, err := o.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow(`SELECT count(*) FROM notices WHERE id=?`, id).Scan(&exists); err != nil {
		return "", err
	}
	if exists != 0 {
		return id, tx.Commit()
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM notices`).Scan(&count); err != nil {
		return "", err
	}
	if count >= MaxEntries {
		return "", ErrFull
	}
	if _, err = tx.Exec(`INSERT INTO notices(id,payload) VALUES(?,?)`, id, payload); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

type Status struct {
	Pending   int `json:"pending"`
	Delivered int `json:"delivered"`
	Rejected  int `json:"rejected"`
}

func (o *Outbox) Status() (Status, error) {
	var s Status
	rows, err := o.db.Query(`SELECT state,count(*) FROM notices GROUP BY state`)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return s, err
		}
		switch state {
		case "pending":
			s.Pending = n
		case "delivered":
			s.Delivered = n
		case "rejected":
			s.Rejected = n
		}
	}
	return s, rows.Err()
}

// Deliver attempts at most limit currently-due notices, serially. Retry delays
// are persisted (1s exponential backoff, capped at 1h). 408/425/429/5xx and
// transport errors retry; other non-2xx responses retain rejected receipts.
// token is read by the caller at runtime and is never stored or returned.
func (o *Outbox) Deliver(ctx context.Context, limit int, token string) error {
	if limit < 1 || limit > MaxEntries || len(token) > 8192 {
		return errors.New("invalid delivery limit or token")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := 0; i < limit; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var id string
		var payload []byte
		var attempts int
		err := o.db.QueryRowContext(ctx, `SELECT id,payload,attempts FROM notices WHERE state='pending' AND due<=? ORDER BY due,id LIMIT 1`, time.Now().UnixNano()).Scan(&id, &payload, &attempts)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(payload) > 4096 {
			return errors.New("outbox payload exceeds limit")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(payload))
		if err != nil {
			return errors.New("invalid webhook request")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", id)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, requestErr := o.client.Do(req)
		status := 0
		if response != nil {
			status = response.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
		}
		state := "pending"
		if requestErr == nil && status >= 200 && status < 300 {
			state = "delivered"
		} else if requestErr == nil && status < 500 && status != 408 && status != 425 && status != 429 {
			state = "rejected"
		}
		delay := time.Second << min(attempts, 12)
		if delay > time.Hour {
			delay = time.Hour
		}
		_, err = o.db.Exec(`UPDATE notices SET attempts=min(attempts+1,2147483647),due=?,state=?,status=? WHERE id=?`, time.Now().Add(delay).UnixNano(), state, status, id)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

func (o *Outbox) Close() error { return o.db.Close() }

// RequireDrained distinguishes a persisted retry backlog from delivery success.
func (s Status) RequireDrained() error {
	if s.Pending != 0 || s.Rejected != 0 {
		return fmt.Errorf("alert delivery incomplete: %d pending, %d rejected", s.Pending, s.Rejected)
	}
	return nil
}
