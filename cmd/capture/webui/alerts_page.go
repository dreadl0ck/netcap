package webui

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/dreadl0ck/netcap/types"
)

// Rows up to about 16 KiB stay on a 64 KiB SQLite page; with 4 KiB pages any
// row above 1,002 bytes, a typical alert, used a whole extra overflow page.
const (
	alertPageMemoryBytes   = 1 << 20
	alertPageDiskPageBytes = 64 << 10
	alertPageDiskBytes     = 512 << 20
)

const errAlertPageScratchFull = "temporary alert page storage is full; narrow the page with groupId or pageSearch"

type alertPageSpill struct {
	dir    string
	db     *sql.DB
	tx     *sql.Tx
	insert *sql.Stmt
}

func (s *alertPageSpill) close() {
	if s.insert != nil {
		s.insert.Close()
		s.insert = nil
	}
	if s.tx != nil {
		s.tx.Rollback()
		s.tx = nil
	}
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
	if s.dir != "" && os.RemoveAll(s.dir) == nil {
		s.dir = ""
	}
}

func (s *alertPageSpill) open(ctx context.Context, diskBytes int) error {
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
		fmt.Sprintf("PRAGMA page_size=%d", alertPageDiskPageBytes),
		fmt.Sprintf("PRAGMA max_page_count=%d", max(1, diskBytes/alertPageDiskPageBytes)),
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
	s.serveRawAlertPageWithBudget(w, r, auditPath, alertPageMemoryBytes, alertPageDiskBytes)
}

func (s *Server) serveRawAlertPageWithBudget(w http.ResponseWriter, r *http.Request, auditPath string, bufferBudget, diskBytes int) {
	options, err := parseCollectionPage(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx := r.Context()
	fail := func(err error) {
		var sqliteErr *sqlite.Error
		if ctx.Err() == nil && errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_FULL {
			RespondJSON(w, http.StatusInsufficientStorage, map[string]string{"error": errAlertPageScratchFull})
			return
		}
		s.respondAlertReadError(w, ctx, err)
	}
	var spill alertPageSpill
	defer spill.close()
	var buffered []json.RawMessage
	q := r.URL.Query()
	severity, rule, group := q.Get("severity"), q.Get("ruleName"), q.Get("groupId")
	search := strings.ToLower(q.Get("pageSearch"))
	kindMatch, err := alertKindFilter(r)
	if err != nil {
		RespondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	match := func(alert *types.Alert) bool {
		return kindMatch(alert) && (severity == "" || strings.EqualFold(alert.Severity, severity)) &&
			(rule == "" || strings.EqualFold(alert.RuleName, rule)) &&
			(group == "" || inAlertGroup(alert, group))
	}
	scanCtx, scanStats := withAlertScanStats(ctx)
	_, err = s.scanFilteredAlertAudit(scanCtx, auditPath, 0, alertStatsScanRows, alertStatsFrameBytes, match, func(alert AlertResponse) error {
		raw, err := json.Marshal(alert)
		if err != nil {
			return err
		}
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
			if err := spill.open(ctx, diskBytes); err != nil {
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
	w.Header().Set("X-Netcap-Skipped-Oversized-Alerts", strconv.Itoa(scanStats.skippedOversized))
	var metadata []map[string]any
	if scanStats.skippedOversized > 0 {
		metadata = append(metadata, map[string]any{"skippedOversizedAlerts": scanStats.skippedOversized})
	}
	if spill.insert == nil {
		slices.SortFunc(buffered, func(a, b json.RawMessage) int { return bytes.Compare(a, b) })
		respondSortedCollectionPage(w, r, "alerts", options, func(yield func(json.RawMessage, error) bool) {
			for _, body := range buffered {
				if !yield(body, nil) {
					return
				}
			}
		}, metadata...)
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
		// Release scratch before writing to the client.
		defer spill.close()
		defer rows.Close()
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
	}, metadata...)
}
