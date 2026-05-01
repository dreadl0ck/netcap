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

package webui

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DashboardChartLayout describes a chart's position and size on a 12-column grid.
type DashboardChartLayout struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

// DashboardChart is one tile inside a dashboard.
type DashboardChart struct {
	ID            string               `json:"id"`
	Title         string               `json:"title"`
	Description   string               `json:"description,omitempty"`
	AuditType     string               `json:"auditType"`
	Field         string               `json:"field"`
	ChartType     string               `json:"chartType"`
	Interval      string               `json:"interval,omitempty"`
	ShowLegend    bool                 `json:"showLegend"`
	MaxDataPoints int                  `json:"maxDataPoints,omitempty"`
	Layout        DashboardChartLayout `json:"layout"`
}

// Dashboard is a saved collection of charts with layout metadata.
type Dashboard struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Charts      []DashboardChart `json:"charts"`
	GridCols    int              `json:"gridCols"`
	RowHeight   int              `json:"rowHeight"`
	CreatedAt   int64            `json:"createdAt"`
	UpdatedAt   int64            `json:"updatedAt"`
	Builtin     bool             `json:"builtin,omitempty"`
}

// builtinDashboardsFS holds every built-in dashboard JSON shipped with the
// binary. Filenames are sorted alphabetically and used to drive listing
// order, so prefix files with "01_", "02_", … to control ordering.
//
//go:embed dashboards_builtin/*.json
var builtinDashboardsFS embed.FS

// dashboardIDRegex restricts ids to safe filename characters and bounds the
// length so that a path traversal or oversized filename can never reach disk.
var dashboardIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// errBuiltinReadOnly is returned when a mutation targets the embedded default
// dashboard. Built-in dashboards can only be forked via POST.
var errBuiltinReadOnly = errors.New("built-in dashboards are read-only; create a copy via POST")

// errNoDashboardsLocation signals the dashboards folder cannot be resolved.
// In practice this only fires when os.UserConfigDir() fails on an exotic OS
// and no override has been provided. Translated to HTTP 503.
var errNoDashboardsLocation = errors.New("could not determine a writable dashboards folder location")

// getDashboardsFolderPath returns the on-disk folder for dashboards.
//
// Storage location is global (independent of any single PCAP/output dir) so
// that dashboards survive switching between captures and aggregate views work
// across all PCAPs of the current instance:
//   - dashboardsFolderOverride is used if set (test hook).
//   - service mode: serviceConfig.DataDir/dashboards
//   - local mode:   <os.UserConfigDir>/netcap/dashboards
//
// Returns "" only if every fallback fails.
func (s *Server) getDashboardsFolderPath() string {
	s.mu.RLock()
	override := s.dashboardsFolderOverride
	isServiceMode := s.isServiceMode
	serviceConfig := s.serviceConfig
	s.mu.RUnlock()

	if override != "" {
		return override
	}
	if isServiceMode && serviceConfig != nil {
		return filepath.Join(serviceConfig.DataDir, "dashboards")
	}
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		log.Printf("[WebUI] dashboards: os.UserConfigDir failed (%v); dashboards persistence is unavailable", err)
		return ""
	}
	return filepath.Join(configDir, "netcap", "dashboards")
}

// migrateLegacyDashboards copies dashboards from the pre-1.x per-output-dir
// storage location (filepath.Dir(outDir)/dashboards) into the new global
// folder once. Files already present in the global folder win. After a
// successful migration, a marker file is written so we don't re-scan on every
// request. The migration is best-effort: errors are logged but not surfaced.
func (s *Server) migrateLegacyDashboards() {
	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()
	if outDir == "" {
		return
	}
	legacy := filepath.Join(filepath.Dir(outDir), "dashboards")
	if _, err := os.Stat(legacy); err != nil {
		return
	}
	target := s.getDashboardsFolderPath()
	if target == "" || target == legacy {
		return
	}
	marker := filepath.Join(target, ".migrated_from_legacy")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		log.Printf("[WebUI] dashboards: migration aborted, cannot create %s: %v", target, err)
		return
	}
	entries, err := os.ReadDir(legacy)
	if err != nil {
		log.Printf("[WebUI] dashboards: migration: cannot read %s: %v", legacy, err)
		return
	}
	migrated := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		dst := filepath.Join(target, entry.Name())
		if _, err := os.Stat(dst); err == nil {
			continue // don't overwrite
		}
		data, err := os.ReadFile(filepath.Join(legacy, entry.Name()))
		if err != nil {
			log.Printf("[WebUI] dashboards: migration: read %s failed: %v", entry.Name(), err)
			continue
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			log.Printf("[WebUI] dashboards: migration: write %s failed: %v", dst, err)
			continue
		}
		migrated++
	}
	if migrated > 0 {
		log.Printf("[WebUI] dashboards: migrated %d legacy dashboard(s) from %s -> %s", migrated, legacy, target)
	}
	_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644)
}

// loadBuiltinDashboards returns freshly-decoded copies of every dashboard
// embedded under dashboards_builtin/. Each result is marked Builtin=true so
// the UI hides destructive actions (rename/delete) and forks them on Save.
//
// Files are loaded in alphabetical order; prefix names with "NN_" to control
// the ordering presented to the user.
func loadBuiltinDashboards() ([]*Dashboard, error) {
	entries, err := builtinDashboardsFS.ReadDir("dashboards_builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded builtin dashboards dir: %w", err)
	}
	out := make([]*Dashboard, 0, len(entries))
	now := time.Now().Unix()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := builtinDashboardsFS.ReadFile(filepath.ToSlash(filepath.Join("dashboards_builtin", entry.Name())))
		if err != nil {
			log.Printf("[WebUI] dashboards: failed to read embedded builtin %s: %v", entry.Name(), err)
			continue
		}
		var d Dashboard
		if err := json.Unmarshal(data, &d); err != nil {
			log.Printf("[WebUI] dashboards: failed to parse embedded builtin %s: %v", entry.Name(), err)
			continue
		}
		if d.GridCols == 0 {
			d.GridCols = 12
		}
		if d.RowHeight == 0 {
			d.RowHeight = 80
		}
		d.Builtin = true
		if d.CreatedAt == 0 {
			d.CreatedAt = now
		}
		if d.UpdatedAt == 0 {
			d.UpdatedAt = now
		}
		out = append(out, &d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no embedded builtin dashboards found")
	}
	return out, nil
}

// listDashboards returns user dashboards (file-based) plus the embedded default
// if no user dashboards exist yet. Errors reading individual files are logged
// and the affected entry is skipped — a single corrupt file does not break the
// whole list.
func (s *Server) listDashboards() ([]*Dashboard, error) {
	// Best-effort migration of any pre-1.x per-PCAP dashboards into the new
	// global location. Idempotent (marker file).
	s.migrateLegacyDashboards()
	folder := s.getDashboardsFolderPath()
	out := make([]*Dashboard, 0)

	if folder != "" {
		entries, err := os.ReadDir(folder)
		switch {
		case err == nil:
			// proceed
		case errors.Is(err, fs.ErrNotExist):
			// folder missing is fine — no dashboards saved yet
		default:
			// Permission or IO error: log, but still return the embedded
			// default so the UI is usable instead of 500-ing.
			log.Printf("[WebUI] dashboards: failed to read folder %s: %v (returning embedded default only)", folder, err)
			entries = nil
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(folder, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				log.Printf("[WebUI] dashboards: failed to read %s: %v", path, err)
				continue
			}
			var d Dashboard
			if err := json.Unmarshal(data, &d); err != nil {
				log.Printf("[WebUI] dashboards: failed to parse %s: %v", path, err)
				continue
			}
			if d.ID == "" {
				d.ID = strings.TrimSuffix(entry.Name(), ".json")
			}
			out = append(out, &d)
		}
	}

	if len(out) == 0 {
		// No user dashboards yet -> seed the listing with every embedded
		// builtin so first-time users discover the security audit views.
		builtins, err := loadBuiltinDashboards()
		if err != nil {
			log.Printf("[WebUI] dashboards: failed to load embedded builtins: %v", err)
		}
		out = append(out, builtins...)
		// Builtin order is determined by filename in the embed; preserve it.
		return out, nil
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt != out[j].UpdatedAt {
			return out[i].UpdatedAt > out[j].UpdatedAt
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// getDashboard fetches a single dashboard by id. The embedded default is returned
// when its id is requested and no on-disk file exists with that id.
func (s *Server) getDashboard(id string) (*Dashboard, error) {
	if !dashboardIDRegex.MatchString(id) {
		return nil, fmt.Errorf("invalid dashboard id")
	}
	folder := s.getDashboardsFolderPath()
	if folder != "" {
		path := filepath.Join(folder, id+".json")
		data, err := os.ReadFile(path)
		if err == nil {
			var d Dashboard
			if uerr := json.Unmarshal(data, &d); uerr != nil {
				return nil, fmt.Errorf("failed to parse dashboard %s: %w", id, uerr)
			}
			if d.ID == "" {
				d.ID = id
			}
			return &d, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("failed to read dashboard %s: %w", id, err)
		}
	}

	builtins, err := loadBuiltinDashboards()
	if err != nil {
		return nil, err
	}
	for _, b := range builtins {
		if b.ID == id {
			return b, nil
		}
	}
	return nil, fs.ErrNotExist
}

// dashboardExistsOnDisk reports whether a user-saved file exists for this id.
// Used to distinguish a user-modifiable dashboard from the embedded default.
func (s *Server) dashboardExistsOnDisk(id string) bool {
	folder := s.getDashboardsFolderPath()
	if folder == "" {
		return false
	}
	if !dashboardIDRegex.MatchString(id) {
		return false
	}
	_, err := os.Stat(filepath.Join(folder, id+".json"))
	return err == nil
}

// saveDashboard persists the dashboard to disk atomically. Best-effort cleanup
// of the .tmp file is performed if the rename step fails.
func (s *Server) saveDashboard(d *Dashboard) error {
	if !dashboardIDRegex.MatchString(d.ID) {
		return fmt.Errorf("invalid dashboard id")
	}
	folder := s.getDashboardsFolderPath()
	if folder == "" {
		return errNoDashboardsLocation
	}
	if err := os.MkdirAll(folder, 0o755); err != nil {
		return fmt.Errorf("failed to create dashboards folder %s: %w", folder, err)
	}
	path := filepath.Join(folder, d.ID+".json")
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode dashboard %s: %w", d.ID, err)
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("failed to write dashboard %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		// Best-effort cleanup so we don't leave stale .tmp files behind.
		if rmErr := os.Remove(tmp); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			log.Printf("[WebUI] dashboards: failed to remove stale tmp file %s: %v", tmp, rmErr)
		}
		return fmt.Errorf("failed to commit dashboard %s: %w", d.ID, err)
	}
	return nil
}

// deleteDashboard removes a dashboard file from disk.
func (s *Server) deleteDashboard(id string) error {
	if !dashboardIDRegex.MatchString(id) {
		return fmt.Errorf("invalid dashboard id")
	}
	folder := s.getDashboardsFolderPath()
	if folder == "" {
		return errNoDashboardsLocation
	}
	path := filepath.Join(folder, id+".json")
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func newDashboardID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Fallback to timestamp; collision improbable for single-user tool.
		log.Printf("[WebUI] dashboards: crypto/rand failed (%v); falling back to time-based id", err)
		return fmt.Sprintf("d-%d", time.Now().UnixNano())
	}
	return "d-" + hex.EncodeToString(buf)
}

func newChartID() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("[WebUI] dashboards: crypto/rand failed for chart id (%v); falling back to time-based id", err)
		return fmt.Sprintf("c-%d", time.Now().UnixNano())
	}
	return "c-" + hex.EncodeToString(buf)
}

// normalizeDashboard fills in defaults and assigns missing chart IDs.
func normalizeDashboard(d *Dashboard) {
	if d.GridCols <= 0 {
		d.GridCols = 12
	}
	if d.RowHeight <= 0 {
		d.RowHeight = 80
	}
	for i := range d.Charts {
		c := &d.Charts[i]
		if c.ID == "" {
			c.ID = newChartID()
		}
		if c.Layout.W <= 0 {
			c.Layout.W = 6
		}
		if c.Layout.H <= 0 {
			c.Layout.H = 4
		}
		if c.MaxDataPoints <= 0 {
			c.MaxDataPoints = 1000
		}
		if c.ChartType == "" {
			c.ChartType = "line"
		}
	}
}

// writeError writes an HTTP error response and logs it on the server side.
// Logging is the only place the underlying error string is preserved verbatim;
// the body returned to clients can be sanitized via msg if needed.
func writeError(w http.ResponseWriter, code int, msg string, err error) {
	if err != nil {
		log.Printf("[WebUI] dashboards: %s: %v (status=%d)", msg, err, code)
	} else {
		log.Printf("[WebUI] dashboards: %s (status=%d)", msg, code)
	}
	if err != nil {
		http.Error(w, msg+": "+err.Error(), code)
		return
	}
	http.Error(w, msg, code)
}

// statusForSaveError maps a saveDashboard error to the appropriate HTTP status.
func statusForSaveError(err error) int {
	switch {
	case errors.Is(err, errNoDashboardsLocation):
		return http.StatusServiceUnavailable
	case errors.Is(err, fs.ErrPermission):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// handleDashboards: GET list, POST create.
func (s *Server) handleDashboards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dashboards, err := s.listDashboards()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list dashboards", err)
			return
		}
		writeJSON(w, dashboards)
	case http.MethodPost:
		var d Dashboard
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body", err)
			return
		}
		if strings.TrimSpace(d.Name) == "" {
			writeError(w, http.StatusBadRequest, "name is required", nil)
			return
		}
		// Server assigns id and timestamps; ignore client values.
		d.ID = newDashboardID()
		d.Builtin = false
		now := time.Now().Unix()
		d.CreatedAt = now
		d.UpdatedAt = now
		normalizeDashboard(&d)
		if err := s.saveDashboard(&d); err != nil {
			writeError(w, statusForSaveError(err), "failed to save dashboard", err)
			return
		}
		log.Printf("[WebUI] dashboards: created %s (%q) with %d charts", d.ID, d.Name, len(d.Charts))
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, &d)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDashboardByID: GET/PUT/DELETE on /api/dashboards/{id}
func (s *Server) handleDashboardByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/dashboards/")
	id = strings.Trim(id, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing dashboard id", nil)
		return
	}
	if !dashboardIDRegex.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid dashboard id", nil)
		return
	}

	switch r.Method {
	case http.MethodGet:
		d, err := s.getDashboard(id)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeError(w, http.StatusNotFound, "dashboard not found", nil)
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to load dashboard", err)
			return
		}
		writeJSON(w, d)
	case http.MethodPut:
		var incoming Dashboard
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body", err)
			return
		}
		if strings.TrimSpace(incoming.Name) == "" {
			writeError(w, http.StatusBadRequest, "name is required", nil)
			return
		}
		// Reject mutations against ids that don't have a user-saved file.
		// The embedded default and unknown ids must be POSTed (forked) instead
		// to avoid silently materializing a built-in into a user dashboard with
		// surprising semantics.
		if !s.dashboardExistsOnDisk(id) {
			writeError(w, http.StatusNotFound, "dashboard not found (use POST to create or fork the built-in)", nil)
			return
		}
		// Preserve created timestamp.
		if existing, err := s.getDashboard(id); err == nil {
			incoming.CreatedAt = existing.CreatedAt
		} else if incoming.CreatedAt == 0 {
			incoming.CreatedAt = time.Now().Unix()
		}
		incoming.ID = id
		incoming.Builtin = false
		incoming.UpdatedAt = time.Now().Unix()
		normalizeDashboard(&incoming)
		if err := s.saveDashboard(&incoming); err != nil {
			writeError(w, statusForSaveError(err), "failed to save dashboard", err)
			return
		}
		log.Printf("[WebUI] dashboards: updated %s (%q) with %d charts", incoming.ID, incoming.Name, len(incoming.Charts))
		writeJSON(w, &incoming)
	case http.MethodDelete:
		if !s.dashboardExistsOnDisk(id) {
			writeError(w, http.StatusNotFound, "dashboard not found", nil)
			return
		}
		if err := s.deleteDashboard(id); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeError(w, http.StatusNotFound, "dashboard not found", nil)
				return
			}
			writeError(w, statusForSaveError(err), "failed to delete dashboard", err)
			return
		}
		log.Printf("[WebUI] dashboards: deleted %s", id)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[WebUI] dashboards: failed to encode response: %v", err)
	}
}
