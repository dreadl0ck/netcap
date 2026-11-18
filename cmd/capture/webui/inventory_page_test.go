package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func TestCollectionPageRejectsIncompleteScans(t *testing.T) {
	row := strings.Repeat("x", 2<<20-2)
	rows := make([]string, 8)
	for i := range rows {
		rows[i] = row
	}
	for _, tc := range []struct {
		name string
		rows []string
		code int
	}{
		{"exact byte cap", rows, http.StatusOK},
		{"over byte cap despite no matches", append(rows, ""), http.StatusRequestEntityTooLarge},
		{"over row cap", make([]string, maxCollectionPageRows+1), http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/hosts?mcpPage=true&pageLimit=1&pageSearch=missing", nil)
			respondCollectionPage(w, r, tc.rows, "hosts")
			if w.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.code, w.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if tc.code == http.StatusOK {
				if string(body["totalCount"]) != "0" || string(body["hosts"]) != "[]" {
					t.Fatalf("expected a complete empty page: %s", w.Body.String())
				}
			} else if body["error"] == nil || body["totalCount"] != nil || body["generation"] != nil || body["hosts"] != nil {
				t.Fatalf("oversized scan returned page evidence: %s", w.Body.String())
			}
		})
	}
}

func TestHostTrafficPageRejectsOversizedAudit(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir}
	writeTimelineAuditFile(t, dir, "Host", types.Type_NC_Host, []proto.Message{
		&types.Host{Addr: "192.0.2.1"},
		&types.Host{Addr: strings.Repeat("x", maxCollectionPageScanBytes)},
	})
	w := httptest.NewRecorder()
	s.handleHosts(w, httptest.NewRequest(http.MethodGet, "/api/hosts?mcpPage=true&pageLimit=1", nil))
	var body map[string]json.RawMessage
	err := json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusRequestEntityTooLarge || err != nil || body["error"] == nil || body["hosts"] != nil || body["generation"] != nil {
		t.Fatalf("expected a scan refusal without page metadata: %d %s", w.Code, w.Body)
	}
}

func TestAlertPagesRejectOversizeSourceBeforeFiltering(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []proto.Message
	}{
		{"records", func() []proto.Message {
			rows := make([]proto.Message, maxCollectionPageRows+1)
			for i := range rows {
				rows[i] = &types.Alert{RuleName: "fixture"}
			}
			return rows
		}()},
		{"record bytes", []proto.Message{&types.Alert{Description: strings.Repeat("x", maxCollectionPageScanBytes)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, tc.rows)
			s := &Server{outDir: dir}
			for path, handler := range map[string]http.HandlerFunc{
				"/api/alerts": s.handleAlerts, "/api/alerts/grouped": s.handleGroupedAlerts, "/api/alerts/stats": s.handleAlertStats,
			} {
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest(http.MethodGet, path+"?mcpPage=true&ruleName=missing&pageLimit=1", nil))
				if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "totalCount") || strings.Contains(w.Body.String(), "totalAlerts") || strings.Contains(w.Body.String(), "generation") {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestAlertPagesRequireValidBoundedResolutionMetadata(t *testing.T) {
	dir := t.TempDir()
	alert := &types.Alert{RuleName: "fixture", Severity: "info", Timestamp: 1}
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{alert})
	s := &Server{outDir: dir}
	request := func(path string, handler http.HandlerFunc, generation string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, path+"?mcpPage=true&pageGeneration="+generation, nil))
		return w
	}
	before := request("/api/alerts", s.handleAlerts, "")
	var page struct {
		Generation string
		Alerts     []AlertResponse
	}
	if err := json.Unmarshal(before.Body.Bytes(), &page); err != nil || before.Code != 200 || len(page.Alerts) != 1 || page.Generation == "" || page.Alerts[0].Resolved {
		t.Fatalf("initial page: %d %s (%v)", before.Code, before.Body, err)
	}
	id := page.Alerts[0].AlertID
	metadata := fmt.Sprintf(`{"alerts":{%q:{"alertId":%q,"resolvedAt":42}}}`, id, id)
	path := s.getResolvedAlertsPath(dir)
	if err := os.WriteFile(path, []byte(metadata+strings.Repeat(" ", maxPageResolvedAlertBytes-len(metadata))), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request("/api/alerts", s.handleAlerts, page.Generation); w.Code != http.StatusConflict {
		t.Fatalf("resolution change accepted old generation: %d %s", w.Code, w.Body)
	}
	after := request("/api/alerts", s.handleAlerts, "")
	if err := json.Unmarshal(after.Body.Bytes(), &page); err != nil || after.Code != 200 || len(page.Alerts) != 1 || !page.Alerts[0].Resolved || page.Alerts[0].ResolvedAt != 42 {
		t.Fatalf("exact-cap metadata page: %d %s (%v)", after.Code, after.Body, err)
	}
	for _, tc := range []struct {
		data string
		code int
	}{{strings.Repeat(" ", maxPageResolvedAlertBytes+1), http.StatusRequestEntityTooLarge}, {"{", http.StatusInternalServerError}} {
		if err := os.WriteFile(path, []byte(tc.data), 0600); err != nil {
			t.Fatal(err)
		}
		for route, handler := range map[string]http.HandlerFunc{"/api/alerts": s.handleAlerts, "/api/alerts/grouped": s.handleGroupedAlerts} {
			w := request(route, handler, "")
			if w.Code != tc.code || strings.Contains(w.Body.String(), "generation") {
				t.Fatalf("%s: %d %s", route, w.Code, w.Body)
			}
		}
	}
}

type heldAlertPageResponse struct {
	*httptest.ResponseRecorder
	writing chan struct{}
	release <-chan struct{}
}

func (w heldAlertPageResponse) Write(p []byte) (int, error) {
	select {
	case w.writing <- struct{}{}:
	default:
	}
	<-w.release
	return w.ResponseRecorder.Write(p)
}

func TestMCPHostViewsShareCapacityThroughResponseWrite(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	release := make(chan struct{})
	var workers sync.WaitGroup
	finish := sync.OnceFunc(func() { close(release); workers.Wait() })
	t.Cleanup(finish)
	for _, view := range []string{"traffic", "identity"} {
		w := heldAlertPageResponse{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}, 1), release: release}
		workers.Go(func() {
			s.handleHosts(w, httptest.NewRequest(http.MethodGet, "/api/hosts?mcpPage=true&view="+view, nil))
		})
		select {
		case <-w.writing:
			if w.Code != http.StatusOK {
				t.Fatalf("%s was not admitted: %d", view, w.Code)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not start writing", view)
		}
	}
	request := func() int {
		w := httptest.NewRecorder()
		s.handleHosts(w, httptest.NewRequest(http.MethodGet, "/api/hosts?mcpPage=true&view=directory", nil))
		return w.Code
	}
	if got := request(); got != http.StatusTooManyRequests {
		t.Fatalf("directory request at capacity: %d", got)
	}
	finish()
	if got := request(); got != http.StatusOK {
		t.Fatalf("directory request after release: %d", got)
	}
}

func TestMCPAlertPagesShareCapacityThroughResponseWrite(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	routes := []struct {
		path string
		get  http.HandlerFunc
	}{{"/api/alerts", s.handleAlerts}, {"/api/alerts/grouped", s.handleGroupedAlerts}}
	var finish []func()
	for _, route := range routes {
		w := heldAlertPageResponse{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}, 1)}
		release, done := make(chan struct{}), make(chan struct{})
		w.release = release
		unblock := sync.OnceFunc(func() { close(release) })
		wait := func() { unblock(); <-done }
		t.Cleanup(wait)
		finish = append(finish, wait)
		go func() {
			defer close(done)
			route.get(w, httptest.NewRequest(http.MethodGet, route.path+"?mcpPage=true", nil))
		}()
		select {
		case <-w.writing:
			if w.Code != http.StatusOK {
				t.Fatalf("first two pages must be admitted: %s returned %d", route.path, w.Code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("admitted page did not start writing")
		}
	}
	for _, route := range routes {
		for _, tc := range []struct {
			query  string
			status int
		}{{"?mcpPage=true", http.StatusTooManyRequests}, {"", http.StatusOK}} {
			w := httptest.NewRecorder()
			route.get(w, httptest.NewRequest(http.MethodGet, route.path+tc.query, nil))
			if w.Code != tc.status {
				t.Fatalf("%s%s: got %d, want %d", route.path, tc.query, w.Code, tc.status)
			}
		}
	}
	stats := httptest.NewRecorder()
	s.handleAlertStats(stats, httptest.NewRequest(http.MethodGet, "/api/alerts/stats", nil))
	if stats.Code != http.StatusTooManyRequests {
		t.Fatalf("stats did not share alert capacity: %d %s", stats.Code, stats.Body)
	}
	for _, wait := range finish {
		wait()
	}
	stats = httptest.NewRecorder()
	s.handleAlertStats(stats, httptest.NewRequest(http.MethodGet, "/api/alerts/stats", nil))
	if stats.Code != http.StatusOK || !strings.Contains(stats.Body.String(), `"totalAlerts":0`) {
		t.Fatalf("stats after release: %d %s", stats.Code, stats.Body)
	}
	for _, route := range routes {
		w := httptest.NewRecorder()
		route.get(w, httptest.NewRequest(http.MethodGet, route.path+"?mcpPage=true", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s did not recover capacity: %d", route.path, w.Code)
		}
	}
}

func TestInventoryHandlersApplySearchAndPaging(t *testing.T) {
	dir := t.TempDir()
	s := &Server{outDir: dir}
	config := &rules.Config{}
	s.rulesConfig = config
	sets := map[string][]proto.Message{}
	if err := os.Mkdir(filepath.Join(dir, "files"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := range 61 {
		name := fmt.Sprintf("needle-%03d", i)
		sets["Host"] = append(sets["Host"], &types.Host{Addr: name})
		sets["Service"] = append(sets["Service"], &types.Service{IP: name, Name: name})
		sets["DeviceProfile"] = append(sets["DeviceProfile"], &types.DeviceProfile{MacAddr: name})
		sets["HTTP"] = append(sets["HTTP"], &types.HTTP{Host: name, Method: "GET"})
		sets["DNS"] = append(sets["DNS"], &types.DNS{Questions: []*types.DNSQuestion{{Name: name, Type: 1}, {Name: name, Type: 28}}})
		sets["TLSCertificate"] = append(sets["TLSCertificate"], &types.TLSCertificate{SHA256Fingerprint: name})
		sets["Secret"] = append(sets["Secret"], &types.Secret{User: name})
		sets["Software"] = append(sets["Software"], &types.Software{Product: name, DeviceProfiles: []string{"z", "a"}, CommunityIDs: []string{"z", "a"}})
		sets["Alert"] = append(sets["Alert"], &types.Alert{RuleName: name, Timestamp: int64(i)})
		config.Rules = append(config.Rules, &rules.Rule{Name: name, Enabled: true})
		if err := os.WriteFile(filepath.Join(dir, "files", name+".bin"), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, rows := range sets {
		writeTimelineAuditFile(t, dir, name, types.Type(types.Type_value["NC_"+name]), rows)
	}
	for key, handler := range map[string]http.HandlerFunc{"hosts": s.handleHosts, "services": s.handleServices, "devices": s.handleDevices, "http": s.handleHTTP, "domains": s.handleDomains, "certificates": s.handleCertificates, "secrets": s.handleSecrets, "software": s.handleSoftware, "alerts": s.handleAlerts, "rules": s.handleGetRules, "files": s.handleExtractedFiles} {
		t.Run(key, func(t *testing.T) {
			for _, tc := range []struct {
				search       string
				total, count int
			}{{"needle", 61, 3}, {"needle-060", 1, 1}, {"absent", 0, 0}} {
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest("GET", "/api/test?mcpPage=true&pageLimit=3&pageSearch="+tc.search, nil))
				if w.Code != 200 {
					t.Fatalf("%d %s", w.Code, w.Body.String())
				}
				var page map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
					t.Fatal(err)
				}
				var rows []json.RawMessage
				if err := json.Unmarshal(page[key], &rows); err != nil {
					t.Fatal(key, err)
				}
				var total int
				json.Unmarshal(page["totalCount"], &total)
				if total != tc.total || len(rows) != tc.count {
					t.Fatalf("search=%s total=%d rows=%d", tc.search, total, len(rows))
				}
				var generation string
				json.Unmarshal(page["generation"], &generation)
				for range 5 {
					repeated := httptest.NewRecorder()
					handler(repeated, httptest.NewRequest("GET", "/api/test?mcpPage=true&pageLimit=3&pageSearch="+tc.search+"&pageGeneration="+generation, nil))
					if repeated.Code != 200 || repeated.Body.String() != w.Body.String() {
						t.Fatalf("unstable %s page: %d", key, repeated.Code)
					}
				}
			}
		})
	}
}

func TestGroupedAlertPagesCountGroupsAndUnderlyingAlertsSeparately(t *testing.T) {
	dir := t.TempDir()
	var alerts []proto.Message
	for i := range 123 {
		for range 2 {
			alerts = append(alerts, &types.Alert{RuleName: fmt.Sprintf("rule-%03d", i), Severity: "info", Timestamp: int64(i)})
		}
	}
	writeTimelineAuditFile(t, dir, "Alert", types.Type(types.Type_value["NC_Alert"]), alerts)
	s := &Server{outDir: dir}
	offset, seen := 0, make(map[string]bool)
	generation := ""
	for {
		w := httptest.NewRecorder()
		s.handleGroupedAlerts(w, httptest.NewRequest("GET", fmt.Sprintf("/api/alerts/grouped?mcpPage=true&pageLimit=17&pageOffset=%d&pageGeneration=%s", offset, generation), nil))
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var page struct {
			Groups     []GroupedAlert `json:"groups"`
			TotalCount int            `json:"totalCount"`
			GroupCount int            `json:"groupCount"`
			NextOffset int            `json:"next_offset"`
			More       bool           `json:"has_more"`
			Generation string         `json:"generation"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if page.TotalCount != 246 || page.GroupCount != 123 || page.NextOffset != offset+len(page.Groups) {
			t.Fatal("ambiguous group page counts", page)
		}
		for _, group := range page.Groups {
			if seen[group.RuleName] {
				t.Fatal("duplicate group", group.RuleName)
			}
			seen[group.RuleName] = true
		}
		if !page.More {
			break
		}
		offset, generation = page.NextOffset, page.Generation
	}
	if len(seen) != 123 {
		t.Fatal("group pagination lost results", len(seen))
	}
}
