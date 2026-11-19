package webui

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func (s *Server) serveRawAlertPage(w http.ResponseWriter, r *http.Request, auditPath string) {
	options, err := parseCollectionPage(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx := r.Context()
	fail := func(err error) { s.respondAlertReadError(w, ctx, err) }
	dir, err := os.MkdirTemp("", "netcap-alert-page-")
	if err != nil {
		fail(err)
		return
	}
	defer os.RemoveAll(dir)
	path, err := filepath.Abs(filepath.Join(dir, "rows.sqlite"))
	if err != nil {
		fail(err)
		return
	}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: uriPath}).String())
	if err != nil {
		fail(err)
		return
	}
	defer db.Close()
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
			fail(err)
			return
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		fail(err)
		return
	}
	defer tx.Rollback()
	insert, err := tx.PrepareContext(ctx, "INSERT INTO alerts VALUES (?, 1) ON CONFLICT(body) DO UPDATE SET copies=copies+1")
	if err != nil {
		fail(err)
		return
	}
	defer insert.Close()
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
		_, err = insert.ExecContext(ctx, raw)
		return err
	})
	if err != nil {
		fail(err)
		return
	}
	if err := tx.Commit(); err != nil {
		fail(err)
		return
	}
	rows, err := db.QueryContext(ctx, "SELECT body, copies FROM alerts ORDER BY body")
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
