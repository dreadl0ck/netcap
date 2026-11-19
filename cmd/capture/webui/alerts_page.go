package webui

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	_ "modernc.org/sqlite"
)

const alertPageMemoryBytes = 1 << 20

type alertPageSpill struct {
	dir    string
	db     *sql.DB
	tx     *sql.Tx
	insert *sql.Stmt
}

func (s *alertPageSpill) close() {
	if s.insert != nil {
		s.insert.Close()
	}
	if s.tx != nil {
		s.tx.Rollback()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

func (s *alertPageSpill) open(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "netcap-alert-page-")
	if err != nil {
		return err
	}
	s.dir = dir
	path, err := filepath.Abs(filepath.Join(dir, "rows.sqlite"))
	if err != nil {
		return err
	}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: uriPath}).String())
	if err != nil {
		return err
	}
	s.db = db
	db.SetMaxOpenConns(1)
	for _, query := range []string{
		"PRAGMA page_size=4096",
		"PRAGMA max_page_count=131072",
		"PRAGMA cache_size=-2048",
		"PRAGMA mmap_size=0",
		"PRAGMA journal_mode=OFF",
		"CREATE TABLE alerts (body BLOB PRIMARY KEY, copies INTEGER NOT NULL) WITHOUT ROWID",
	} {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	s.tx = tx
	s.insert, err = tx.PrepareContext(ctx, "INSERT INTO alerts VALUES (?, 1) ON CONFLICT(body) DO UPDATE SET copies=copies+1")
	return err
}

func (s *Server) serveRawAlertPage(w http.ResponseWriter, r *http.Request, auditPath string) {
	options, err := parseCollectionPage(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx := r.Context()
	fail := func(err error) { s.respondAlertReadError(w, ctx, err) }
	var spill alertPageSpill
	defer spill.close()
	var buffered []json.RawMessage
	bufferBudget := alertPageMemoryBytes
	q := r.URL.Query()
	severity, rule, group := q.Get("severity"), q.Get("ruleName"), q.Get("groupId")
	search := strings.ToLower(q.Get("pageSearch"))
	remaining := alertStatsScanBytes
	_, err = s.scanAlertAudit(ctx, auditPath, alertStatsScanBytes, alertStatsScanRows, alertStatsFrameBytes, func(alert AlertResponse) error {
		if (severity != "" && !strings.EqualFold(alert.Severity, severity)) ||
			(rule != "" && !strings.EqualFold(alert.RuleName, rule)) ||
			(group != "" && generateGroupID(alert.RuleName, alert.Severity) != group) {
			return nil
		}
		raw, err := json.Marshal(alert)
		if err != nil {
			return err
		}
		if len(raw) > remaining {
			return fmt.Errorf("%w: encoded alert scan exceeds %d bytes", errAlertPageSourceLimit, alertStatsScanBytes)
		}
		remaining -= len(raw)
		if search != "" && !strings.Contains(strings.ToLower(string(raw)), search) {
			return nil
		}
		if spill.insert == nil {
			charge := len(raw) + 32
			if charge <= bufferBudget {
				buffered = append(buffered, raw)
				bufferBudget -= charge
				return nil
			}
			if err := spill.open(ctx); err != nil {
				return err
			}
			for _, body := range buffered {
				if _, err := spill.insert.ExecContext(ctx, []byte(body)); err != nil {
					return err
				}
			}
			buffered = nil
		}
		_, err = spill.insert.ExecContext(ctx, raw)
		return err
	})
	if err != nil {
		fail(err)
		return
	}
	if spill.insert == nil {
		slices.SortFunc(buffered, func(a, b json.RawMessage) int { return bytes.Compare(a, b) })
		respondSortedCollectionPage(w, r, "alerts", options, func(yield func(json.RawMessage, error) bool) {
			for _, body := range buffered {
				if !yield(body, nil) {
					return
				}
			}
		})
		return
	}
	if err := spill.tx.Commit(); err != nil {
		fail(err)
		return
	}
	rows, err := spill.db.QueryContext(ctx, "SELECT body, copies FROM alerts ORDER BY body")
	if err != nil {
		fail(err)
		return
	}
	defer rows.Close()
	respondSortedCollectionPage(w, r, "alerts", options, func(yield func(json.RawMessage, error) bool) {
		for rows.Next() {
			var body []byte
			var copies int
			if err := rows.Scan(&body, &copies); err != nil {
				yield(nil, err)
				return
			}
			for range copies {
				if !yield(body, nil) {
					return
				}
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, err)
		}
	})
}
