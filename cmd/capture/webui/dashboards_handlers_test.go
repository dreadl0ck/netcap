/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newTestServer creates a Server suitable for dashboard CRUD tests using a
// dedicated temp directory pinned via dashboardsFolderOverride so tests don't
// touch the real user-config dir.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	tmp := t.TempDir()
	return &Server{
		outDir:                   filepath.Join(tmp, "out"),
		dashboardsFolderOverride: filepath.Join(tmp, "dashboards"),
	}
}

// TestLoadBuiltinDashboardsEmbedded validates every dashboard JSON shipped in
// dashboards_builtin/ has the required structure: non-empty id/name/charts and
// every chart has a title, description, audit type, field, chart type and a
// non-zero layout box. This catches schema drift early.
func TestLoadBuiltinDashboardsEmbedded(t *testing.T) {
	builtins, err := loadBuiltinDashboards()
	if err != nil {
		t.Fatalf("loadBuiltinDashboards returned error: %v", err)
	}
	if len(builtins) < 5 {
		t.Fatalf("expected at least 5 builtin dashboards, got %d", len(builtins))
	}
	seenIDs := make(map[string]bool)
	for _, d := range builtins {
		if d.ID == "" {
			t.Error("builtin dashboard has empty id")
		}
		if seenIDs[d.ID] {
			t.Errorf("duplicate builtin dashboard id %q", d.ID)
		}
		seenIDs[d.ID] = true
		if d.Name == "" {
			t.Errorf("builtin %q has empty name", d.ID)
		}
		if d.Description == "" {
			t.Errorf("builtin %q has no top-level description", d.ID)
		}
		if !d.Builtin {
			t.Errorf("builtin %q should have Builtin=true", d.ID)
		}
		if len(d.Charts) == 0 {
			t.Errorf("builtin %q has no charts", d.ID)
		}
		for _, c := range d.Charts {
			if c.ID == "" || c.Title == "" || c.AuditType == "" || c.Field == "" || c.ChartType == "" {
				t.Errorf("dashboard %q chart %q missing required fields", d.ID, c.ID)
			}
			if c.Description == "" {
				t.Errorf("dashboard %q chart %q has no description", d.ID, c.ID)
			}
			if c.Layout.W <= 0 || c.Layout.H <= 0 {
				t.Errorf("dashboard %q chart %q has invalid layout %+v", d.ID, c.ID, c.Layout)
			}
		}
	}
}

// TestListDashboardsReturnsAllBuiltinsWhenEmpty asserts that with no user
// dashboards on disk, the listing is the full set of builtins (in filename
// order) so first-time users discover the security audit views.
func TestListDashboardsReturnsAllBuiltinsWhenEmpty(t *testing.T) {
	s := newTestServer(t)
	list, err := s.listDashboards()
	if err != nil {
		t.Fatalf("listDashboards: %v", err)
	}
	if len(list) < 5 {
		t.Fatalf("expected >=5 builtin dashboards, got %d", len(list))
	}
	for _, d := range list {
		if !d.Builtin {
			t.Errorf("dashboard %q expected to be builtin", d.ID)
		}
	}
}

func TestDashboardCRUDFlow(t *testing.T) {
	s := newTestServer(t)

	// CREATE
	body := `{"name":"Test","description":"desc","charts":[{"title":"t","auditType":"HTTP","field":"Method","chartType":"pie","layout":{"x":0,"y":0,"w":6,"h":4}}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/dashboards", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	s.handleDashboards(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created Dashboard
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created dashboard has empty id")
	}
	if len(created.Charts) != 1 || created.Charts[0].ID == "" {
		t.Fatal("chart id was not assigned")
	}

	// LIST (should now contain 1 user dashboard, no default merge)
	rr = httptest.NewRecorder()
	s.handleDashboards(rr, httptest.NewRequest(http.MethodGet, "/api/dashboards", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status %d", rr.Code)
	}
	var list []Dashboard
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("expected just the created dashboard, got %+v", list)
	}

	// GET by id
	rr = httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodGet, "/api/dashboards/"+created.ID, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get: status %d body=%s", rr.Code, rr.Body.String())
	}

	// PUT update
	updated := created
	updated.Name = "Renamed"
	updated.Charts = append(updated.Charts, DashboardChart{
		Title: "second", AuditType: "DNS", Field: "Questions.Name", ChartType: "pie",
		Layout: DashboardChartLayout{X: 6, Y: 0, W: 6, H: 4},
	})
	updBytes, _ := json.Marshal(updated)
	rr = httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodPut, "/api/dashboards/"+created.ID, bytes.NewReader(updBytes)))
	if rr.Code != http.StatusOK {
		t.Fatalf("put: status %d body=%s", rr.Code, rr.Body.String())
	}
	var got Dashboard
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode put: %v", err)
	}
	if got.Name != "Renamed" || len(got.Charts) != 2 {
		t.Errorf("update did not apply: %+v", got)
	}
	if got.Charts[1].ID == "" {
		t.Error("new chart id was not assigned by normalize")
	}

	// DELETE
	rr = httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodDelete, "/api/dashboards/"+created.ID, nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", rr.Code)
	}

	// GET after delete -> 404 (or default if id matched default)
	rr = httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodGet, "/api/dashboards/"+created.ID, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", rr.Code)
	}
}

func TestDashboardIDValidation(t *testing.T) {
	s := newTestServer(t)
	// Use only path-safe candidates; the regex check exercises the validation logic.
	for _, badID := range []string{"..etc", "with$slash", "white.space", "tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo-long"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/dashboards/"+badID, nil)
		s.handleDashboardByID(rr, req)
		if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
			t.Errorf("expected 400/404 for bad id %q, got %d", badID, rr.Code)
		}
	}
}

func TestDashboardPostRequiresName(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/dashboards", bytes.NewBufferString(`{"name":""}`))
	rr := httptest.NewRecorder()
	s.handleDashboards(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty name, got %d", rr.Code)
	}
}

// TestPutOnBuiltinReturnsNotFound enforces that an embedded builtin dashboard
// cannot be mutated in place; clients must POST to fork it.
func TestPutOnBuiltinReturnsNotFound(t *testing.T) {
	s := newTestServer(t)
	builtins, err := loadBuiltinDashboards()
	if err != nil {
		t.Fatalf("loadBuiltinDashboards: %v", err)
	}
	def := builtins[0]
	def.Name = "tampered"
	body, _ := json.Marshal(def)
	rr := httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodPut, "/api/dashboards/"+def.ID, bytes.NewReader(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 PUT on builtin id, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestPutOnUnknownIDReturnsNotFound prevents silent creation of arbitrary ids
// via PUT (only POST may allocate ids).
func TestPutOnUnknownIDReturnsNotFound(t *testing.T) {
	s := newTestServer(t)
	body := `{"name":"X","charts":[],"gridCols":12,"rowHeight":80}`
	rr := httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodPut, "/api/dashboards/does-not-exist", bytes.NewBufferString(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 PUT on unknown id, got %d", rr.Code)
	}
}

// TestDeleteOnBuiltinReturnsNotFound: the embedded builtins have no on-disk
// file so DELETE should report 404 (no destructive op against the embed).
func TestDeleteOnBuiltinReturnsNotFound(t *testing.T) {
	s := newTestServer(t)
	builtins, _ := loadBuiltinDashboards()
	def := builtins[0]
	rr := httptest.NewRecorder()
	s.handleDashboardByID(rr, httptest.NewRequest(http.MethodDelete, "/api/dashboards/"+def.ID, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 DELETE on builtin, got %d", rr.Code)
	}
}

// TestDashboardsFolderUsesOverride confirms the global storage path
// resolution honors the test override and never falls back to a
// per-output-dir location.
func TestDashboardsFolderUsesOverride(t *testing.T) {
	tmp := t.TempDir()
	s := &Server{
		outDir:                   filepath.Join(tmp, "out"),
		dashboardsFolderOverride: filepath.Join(tmp, "global", "dashboards"),
	}
	got := s.getDashboardsFolderPath()
	want := filepath.Join(tmp, "global", "dashboards")
	if got != want {
		t.Fatalf("getDashboardsFolderPath = %q want %q", got, want)
	}
	// Sanity: not the legacy per-pcap location.
	legacy := filepath.Join(filepath.Dir(s.outDir), "dashboards")
	if got == legacy {
		t.Errorf("dashboards folder should not be the legacy per-output-dir location %q", legacy)
	}
}

// TestLegacyDashboardMigration verifies that dashboards in the pre-1.x
// per-PCAP location are copied into the global folder on first list, and
// that subsequent calls do not duplicate the work (marker file present).
func TestLegacyDashboardMigration(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "pcap1", "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	legacy := filepath.Join(filepath.Dir(out), "dashboards")
	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatalf("mkdir legacy: %v", err)
	}
	d := Dashboard{ID: "legacy1", Name: "Legacy"}
	data, _ := json.MarshalIndent(d, "", "  ")
	if err := os.WriteFile(filepath.Join(legacy, "legacy1.json"), data, 0o644); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	s := &Server{
		outDir:                   out,
		dashboardsFolderOverride: filepath.Join(tmp, "global", "dashboards"),
	}
	if _, err := s.listDashboards(); err != nil {
		t.Fatalf("listDashboards: %v", err)
	}
	migrated := filepath.Join(s.dashboardsFolderOverride, "legacy1.json")
	if _, err := os.Stat(migrated); err != nil {
		t.Fatalf("legacy dashboard not migrated to %s: %v", migrated, err)
	}
	marker := filepath.Join(s.dashboardsFolderOverride, ".migrated_from_legacy")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker file missing: %v", err)
	}
	// Removing the migrated file and listing again must not re-migrate
	// (marker present).
	_ = os.Remove(migrated)
	if _, err := s.listDashboards(); err != nil {
		t.Fatalf("listDashboards: %v", err)
	}
	if _, err := os.Stat(migrated); err == nil {
		t.Errorf("migration ran twice; marker file should have prevented re-copy")
	}
}

// TestListDashboardsSurvivesCorruptFile ensures that a single bad file does not
// poison the entire list; the bad entry is skipped and other entries return
// successfully.
func TestListDashboardsSurvivesCorruptFile(t *testing.T) {
	s := newTestServer(t)
	folder := s.getDashboardsFolderPath()
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folder, "bad.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	good := Dashboard{ID: "good", Name: "Good", Charts: []DashboardChart{}, GridCols: 12, RowHeight: 80}
	gb, _ := json.MarshalIndent(good, "", "  ")
	if err := os.WriteFile(filepath.Join(folder, "good.json"), gb, 0o644); err != nil {
		t.Fatalf("write good: %v", err)
	}

	rr := httptest.NewRecorder()
	s.handleDashboards(rr, httptest.NewRequest(http.MethodGet, "/api/dashboards", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list status %d body=%s", rr.Code, rr.Body.String())
	}
	var list []Dashboard
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 1 || list[0].ID != "good" {
		t.Fatalf("expected only good dashboard in list, got %+v", list)
	}
}

// TestPostJSONErrorIs400 ensures malformed JSON returns 400 with a useful body.
func TestPostJSONErrorIs400(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	s.handleDashboards(rr, httptest.NewRequest(http.MethodPost, "/api/dashboards", bytes.NewBufferString("{garbage")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalid JSON")) {
		t.Errorf("response body should mention invalid JSON, got %s", rr.Body.String())
	}
}
