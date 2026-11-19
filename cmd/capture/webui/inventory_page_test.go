package webui

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/delimited"
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

func TestHostTopProtocolsKeepStableCutoff(t *testing.T) {
	protocols := map[string]*types.Protocol{
		"TLS": {Packets: 8}, "HTTP": {Packets: 4}, "DNS": {Packets: 4}, "SSH": nil,
	}
	for range 16 {
		got := extractTopProtocols(protocols, 2)
		if len(got) != 2 || got[0].Name != "TLS" || got[1].Name != "DNS" {
			t.Fatalf("unexpected protocol ranking: %+v", got)
		}
	}
}

func TestHostTopPortsKeepStableCutoff(t *testing.T) {
	ports := []*types.Port{
		{PortNumber: 443, Protocol: "tcp", Stats: &types.PortStats{Packets: 6}},
		{PortNumber: 53, Protocol: "udp", Stats: &types.PortStats{Packets: 6}},
		{PortNumber: 443, Protocol: "udp", Stats: &types.PortStats{Packets: 7}},
		{PortNumber: 53, Protocol: "tcp", Stats: &types.PortStats{Packets: 6}},
		nil, {PortNumber: 25},
	}
	for range len(ports) {
		got := extractTopPorts(ports, 2)
		if len(got) != 2 || got[0].Port != 443 || got[0].Protocol != "udp" || got[1].Port != 53 || got[1].Protocol != "tcp" {
			t.Fatalf("unstable top two: %+v", got)
		}
		first := ports[0]
		copy(ports, ports[1:])
		ports[len(ports)-1] = first
	}
}

func TestDomainInventoryBoundsAnswerAssociations(t *testing.T) {
	dir := t.TempDir()
	questions := make([]*types.DNSQuestion, 1024)
	for i := range questions {
		questions[i] = &types.DNSQuestion{Name: "fixture.test"}
	}
	answers := make([]*types.DNSResourceRecord, 1025)
	for i := range answers {
		answers[i] = &types.DNSResourceRecord{IP: "192.0.2.1"}
	}
	s := &Server{outDir: dir}
	for _, tc := range []struct{ count, status int }{{1024, 200}, {1025, 413}} {
		writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{&types.DNS{Questions: questions, Answers: answers[:tc.count]}})
		w := httptest.NewRecorder()
		s.handleDomains(w, httptest.NewRequest(http.MethodGet, "/api/domains?mcpPage=true&pageLimit=1", nil))
		var result map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != tc.status {
			t.Fatalf("%d answers: status=%d body=%s err=%v", tc.count, w.Code, w.Body, err)
		}
		if tc.status == 200 && (!strings.Contains(string(result["domains"]), "192.0.2.1") || string(result["totalCount"]) != "1") {
			t.Fatalf("exact budget lost the resolved address: %s", w.Body)
		}
		if tc.status == 413 && (result["domains"] != nil || result["generation"] != nil) {
			t.Fatalf("overrun published a partial page: %s", w.Body)
		}
	}
}

func TestDeviceInventoryRejectsOversizedAudit(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "DeviceProfile", types.Type_NC_DeviceProfile, []proto.Message{
		&types.DeviceProfile{MacAddr: "02:00:00:00:00:01"},
		&types.DeviceProfile{OS: strings.Repeat("x", maxCollectionPageScanBytes)},
	})
	w := httptest.NewRecorder()
	(&Server{outDir: dir}).handleDevices(w, httptest.NewRequest(http.MethodGet, "/api/devices?mcpPage=true&pageLimit=1", nil))
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "generation") || strings.Contains(w.Body.String(), "02:00:00:00:00:01") {
		t.Fatalf("expected refusal without a partial device page: %d %s", w.Code, w.Body)
	}
}

func TestServiceInventoryRejectsOversizedAudit(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "Service", types.Type_NC_Service, []proto.Message{
		&types.Service{Name: "fixture-service"},
		&types.Service{Banner: strings.Repeat("x", maxCollectionPageScanBytes)},
	})
	w := httptest.NewRecorder()
	(&Server{outDir: dir}).handleServices(w, httptest.NewRequest(http.MethodGet, "/api/services?mcpPage=true&pageLimit=1", nil))
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "generation") || strings.Contains(w.Body.String(), "fixture-service") {
		t.Fatalf("expected refusal without a partial service page: %d %s", w.Code, w.Body)
	}
}

func TestSoftwareInventoryRejectsOversizedAudit(t *testing.T) {
	dir := t.TempDir()
	s := newTimelineTestServer(dir)
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSoftware(w, httptest.NewRequest(http.MethodGet, "/api/software?mcpPage=true&pageLimit=1", nil))
		return w
	}
	writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, []proto.Message{
		&types.Software{Product: "fixture-software"},
		&types.Software{Product: strings.Repeat("x", maxCollectionPageScanBytes)},
	})
	w := request()
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "generation") || strings.Contains(w.Body.String(), "fixture-software") {
		t.Fatalf("expected refusal without a partial software page: %d %s", w.Code, w.Body)
	}
	writeTimelineAuditFile(t, dir, "Software", types.Type_NC_Software, []proto.Message{
		&types.Software{Product: "z-product"}, &types.Software{Product: "a-product"},
	})
	for range 8 {
		w = request()
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"product":"a-product"`) || strings.Contains(w.Body.String(), "z-product") {
			t.Fatalf("retry did not return the first tied product: %d %s", w.Code, w.Body)
		}
	}
}

func TestMCPSoftwareInventoryLimitsConcurrentResponses(t *testing.T) {
	s := newTimelineTestServer(t.TempDir())
	testInventoryResponseCapacity(t, "/api/software", s.handleSoftware)
}

func TestCertificateInventoryRejectsOversizedAudit(t *testing.T) {
	dir := t.TempDir()
	s := newTimelineTestServer(dir)
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleCertificates(w, httptest.NewRequest(http.MethodGet, "/api/certificates?mcpPage=true&pageLimit=1", nil))
		return w
	}
	writeTimelineAuditFile(t, dir, "TLSCertificate", types.Type_NC_TLSCertificate, []proto.Message{
		&types.TLSCertificate{SHA256Fingerprint: "first-certificate"},
		&types.TLSCertificate{SubjectCommonName: strings.Repeat("x", maxCollectionPageScanBytes)},
	})
	w := request()
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "generation") || strings.Contains(w.Body.String(), "first-certificate") {
		t.Fatalf("expected refusal without a partial certificate page: %d %s", w.Code, w.Body)
	}
	writeTimelineAuditFile(t, dir, "TLSCertificate", types.Type_NC_TLSCertificate, []proto.Message{
		&types.TLSCertificate{SHA256Fingerprint: "z-certificate"}, &types.TLSCertificate{SHA256Fingerprint: "a-certificate"},
	})
	for range 8 {
		w = request()
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"sha256Fingerprint":"a-certificate"`) || strings.Contains(w.Body.String(), "z-certificate") {
			t.Fatalf("retry did not return the first tied certificate: %d %s", w.Code, w.Body)
		}
	}
}

func TestMCPCertificateInventoryLimitsConcurrentResponses(t *testing.T) {
	s := newTimelineTestServer(t.TempDir())
	testInventoryResponseCapacity(t, "/api/certificates", s.handleCertificates)
}

func TestSecretInventoryBoundsBothEncodings(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		name := "plain"
		if compressed {
			name = "gzip"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := newTimelineTestServer(dir)
			request := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				s.handleSecrets(w, httptest.NewRequest(http.MethodGet, "/api/secrets?mcpPage=true&pageLimit=1", nil))
				return w
			}
			write := func(rows []proto.Message) {
				if compressed {
					writeTimelineAuditFile(t, dir, "Secret", types.Type_NC_Secret, rows)
				} else {
					writeTimelineAuditFilePlain(t, dir, "Secret", types.Type_NC_Secret, rows)
				}
			}
			fixture := &types.Secret{User: "fixture-user"}
			write([]proto.Message{fixture, &types.Secret{Value: strings.Repeat("x", maxCollectionPageScanBytes)}})
			w := request()
			if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "generation") || strings.Contains(w.Body.String(), "fixture-user") {
				t.Fatalf("expected limit error only: %d %s", w.Code, w.Body)
			}
			write([]proto.Message{fixture, &types.Secret{}})
			w = request()
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user":"fixture-user"`) || !strings.Contains(w.Body.String(), `"totalCount":1`) {
				t.Fatalf("retry did not retain exactly one row: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestMCPSecretInventoryLimitsConcurrentResponses(t *testing.T) {
	s := newTimelineTestServer(t.TempDir())
	testInventoryResponseCapacity(t, "/api/secrets", s.handleSecrets)
}

func TestDomainInventorySharesAuditBudget(t *testing.T) {
	dir := t.TempDir()
	writeTimelineAuditFile(t, dir, "DNS", types.Type_NC_DNS, []proto.Message{&types.DNS{}})
	writeTimelineAuditFile(t, dir, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{Sni: "fixture.test"}})
	budget := inventoryAuditBudget{ctx: context.Background(), stored: maxCollectionPageScanBytes, bodies: maxCollectionPageScanBytes, rows: 2}
	rows, err := readDomainInventory(dir, &budget)
	if err != nil || len(rows) != 1 || rows[0].Domain != "fixture.test" {
		t.Fatalf("exact combined budget: rows=%v err=%v", rows, err)
	}
	short := inventoryAuditBudget{ctx: context.Background(), stored: maxCollectionPageScanBytes, bodies: maxCollectionPageScanBytes, rows: 1}
	if rows, err := readDomainInventory(dir, &short); rows != nil || !errors.Is(err, errInventoryAuditLimit) {
		t.Fatalf("short combined budget: rows=%v err=%v", rows, err)
	}
}

func TestHTTPInventoryRejectsIncompleteAudit(t *testing.T) {
	for _, oversized := range []bool{true, false} {
		t.Run(fmt.Sprintf("oversized=%t", oversized), func(t *testing.T) {
			dir := t.TempDir()
			rows := []proto.Message{&types.HTTP{Method: "GET", URL: "/valid"}}
			status := http.StatusInternalServerError
			if oversized {
				rows = append(rows, &types.HTTP{RequestBody: make([]byte, maxCollectionPageScanBytes)})
				status = http.StatusRequestEntityTooLarge
			}
			writeTimelineAuditFile(t, dir, "HTTP", types.Type_NC_HTTP, rows)
			if !oversized {
				path := filepath.Join(dir, "HTTP.ncap.gz")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-8] ^= 1 // Corrupt the gzip checksum after the valid row.
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			(&Server{outDir: dir}).handleHTTP(w, httptest.NewRequest(http.MethodGet, "/api/http?mcpPage=true&pageLimit=1", nil))
			if w.Code != status || strings.Contains(w.Body.String(), "generation") || strings.Contains(w.Body.String(), "/valid") {
				t.Fatalf("expected refusal without a partial page: %d %s", w.Code, w.Body)
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
		{"record bytes", []proto.Message{&types.Alert{Description: strings.Repeat("x", maxCollectionPageScanBytes)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, tc.rows)
			s := &Server{outDir: dir}
			for path, handler := range map[string]http.HandlerFunc{
				"/api/alerts": s.handleAlerts, "/api/alerts/grouped": s.handleGroupedAlerts,
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

func TestAlertAuditGrowthRejectsSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{&types.Alert{RuleName: "fixture"}})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: dir}
	_, err = s.scanAlertAudit(t.Context(), path, alertStatsScanBytes, alertStatsScanRows, alertStatsFrameBytes, func(AlertResponse) error {
		return os.Truncate(path, info.Size()+1)
	})
	if !errors.Is(err, errAlertAuditChanged) {
		t.Fatalf("expected changing audit to be rejected, got %v", err)
	}
	w := httptest.NewRecorder()
	s.respondAlertReadError(w, t.Context(), err)
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "totalAlerts") {
		t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
	}
}

func TestRawAlertPageSpillPreservesDuplicateContinuation(t *testing.T) {
	dir := t.TempDir()
	duplicate := &types.Alert{RuleName: "fixture", Timestamp: 2_000_000}
	path := writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, []proto.Message{
		duplicate, &types.Alert{RuleName: "fixture", Timestamp: 1_000_000}, duplicate,
	})
	s := &Server{outDir: dir}
	first := httptest.NewRecorder()
	s.handleAlerts(first, httptest.NewRequest(http.MethodGet, "/api/alerts?mcpPage=true&pageLimit=2", nil))
	var page struct {
		Alerts     []AlertResponse
		TotalCount int
		Generation string
	}
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil || first.Code != http.StatusOK || page.TotalCount != 3 || len(page.Alerts) != 2 || page.Alerts[0].Timestamp != 1 || page.Alerts[1].Timestamp != 2 || page.Generation == "" {
		t.Fatalf("unexpected initial page: %d %s (%v)", first.Code, first.Body, err)
	}
	url := "/api/alerts?mcpPage=true&pageLimit=2&pageOffset=2&pageGeneration=" + page.Generation
	memory, spilled := httptest.NewRecorder(), httptest.NewRecorder()
	s.handleAlerts(memory, httptest.NewRequest(http.MethodGet, url, nil))
	s.serveRawAlertPageWithBudget(spilled, httptest.NewRequest(http.MethodGet, url, nil), path, 0)
	if memory.Code != http.StatusOK || spilled.Code != http.StatusOK || memory.Body.String() != spilled.Body.String() {
		t.Fatalf("continuation differs: memory=%d %s; spill=%d %s", memory.Code, memory.Body, spilled.Code, spilled.Body)
	}
	page.Alerts = nil
	if err := json.Unmarshal(spilled.Body.Bytes(), &page); err != nil || page.TotalCount != 3 || len(page.Alerts) != 1 || page.Alerts[0].Timestamp != 2 {
		t.Fatalf("duplicate lost at page boundary: %s (%v)", spilled.Body, err)
	}
}

func TestAlertViewsAbovePageScanBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Alert.ncap.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewWriterLevel(f, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	w := delimited.NewWriter(gz)
	if err := w.PutProto(&types.Header{Type: types.Type_NC_Alert}); err != nil {
		t.Fatal(err)
	}
	const count = 27152
	for i := range count {
		severity := "info"
		if i%2 == 0 {
			severity = "critical"
		}
		if err := w.PutProto(&types.Alert{RuleName: "fixture", Severity: severity, Timestamp: int64(i+1) * int64(time.Millisecond), Description: strings.Repeat("x", 640)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil || info.Size() <= maxCollectionPageScanBytes {
		t.Fatalf("fixture did not exceed the old stored-size cap: %v, %v", info, err)
	}
	s := &Server{outDir: dir}
	response := httptest.NewRecorder()
	s.handleAlertStats(response, httptest.NewRequest(http.MethodGet, "/api/alerts/stats", nil))
	var stats struct {
		TotalAlerts    int
		GroupCount     int
		CriticalAlerts int
		ByRule         map[string]int
		RecentAlerts   []AlertResponse
	}
	if err := json.Unmarshal(response.Body.Bytes(), &stats); err != nil || response.Code != http.StatusOK || stats.TotalAlerts != count || stats.CriticalAlerts != count/2 || stats.GroupCount != 2 || stats.ByRule["fixture"] != count || len(stats.RecentAlerts) != 10 {
		t.Fatalf("unexpected alert statistics: status=%d total=%d recent=%d error=%v", response.Code, stats.TotalAlerts, len(stats.RecentAlerts), err)
	}
	for i, alert := range stats.RecentAlerts {
		if alert.Timestamp != int64(count-i) {
			t.Fatalf("recent alert %d: timestamp=%d", i, alert.Timestamp)
		}
	}
	// Timestamp is the first varying field in the fixture's serialized alerts.
	ordered := make([]string, count)
	for i := range ordered {
		ordered[i] = strconv.Itoa(i+1) + ","
	}
	sort.Strings(ordered)
	var generation string
	for _, offset := range []int{0, 25_000, count - 2, count} {
		response := httptest.NewRecorder()
		url := fmt.Sprintf("/api/alerts?mcpPage=true&pageLimit=2&pageOffset=%d&pageFields=timestamp&pageGeneration=%s", offset, generation)
		s.handleAlerts(response, httptest.NewRequest(http.MethodGet, url, nil))
		var page struct {
			Alerts     []AlertResponse
			TotalCount int
			Generation string
			HasMore    bool `json:"has_more"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || response.Code != http.StatusOK || page.TotalCount != count || page.Alerts == nil || len(page.Alerts) != min(2, count-offset) || page.HasMore != (offset+2 < count) || page.Generation == "" || (generation != "" && generation != page.Generation) {
			t.Fatalf("offset %d: status=%d body=%s err=%v", offset, response.Code, response.Body, err)
		}
		generation = page.Generation
		for i, alert := range page.Alerts {
			if strconv.FormatInt(alert.Timestamp, 10)+"," != ordered[offset+i] {
				t.Fatalf("offset %d row %d: timestamp=%d, want %s", offset, i, alert.Timestamp, ordered[offset+i])
			}
		}
	}
	generation = ""
	for _, offset := range []int{0, 1, 2} {
		response := httptest.NewRecorder()
		url := fmt.Sprintf("/api/alerts/grouped?mcpPage=true&pageLimit=1&pageOffset=%d&pageGeneration=%s", offset, generation)
		s.handleGroupedAlerts(response, httptest.NewRequest(http.MethodGet, url, nil))
		var page struct {
			Groups                 []GroupedAlert
			TotalCount, GroupCount int
			Generation             string
			HasMore                bool `json:"has_more"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || response.Code != http.StatusOK || page.TotalCount != count || page.GroupCount != 2 || page.Groups == nil || len(page.Groups) != min(1, 2-offset) || page.HasMore != (offset == 0) || page.Generation == "" || (generation != "" && generation != page.Generation) {
			t.Fatalf("group offset %d: status=%d body=%s err=%v", offset, response.Code, response.Body, err)
		}
		generation = page.Generation
		if offset < 2 && page.Groups[0].Count != count/2 {
			t.Fatalf("group offset %d: count=%d", offset, page.Groups[0].Count)
		}
	}
}

func TestGroupedAlertPagesRejectExcessSummaryState(t *testing.T) {
	dir := t.TempDir()
	rows := make([]proto.Message, 10_000)
	for i := range rows {
		rows[i] = &types.Alert{RuleName: fmt.Sprintf("rule-%05d", i), Severity: "info"}
	}
	writeTimelineAuditFile(t, dir, "Alert", types.Type_NC_Alert, rows)
	s := &Server{outDir: dir}
	w := httptest.NewRecorder()
	s.handleGroupedAlerts(w, httptest.NewRequest(http.MethodGet, "/api/alerts/grouped?mcpPage=true&pageLimit=1", nil))
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "grouped alert state budget") || strings.Contains(w.Body.String(), "totalCount") {
		t.Fatalf("unexpected grouped budget response: %d %s", w.Code, w.Body.String())
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

func TestMCPHTTPInventoryLimitsConcurrentResponses(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	testInventoryResponseCapacity(t, "/api/http", s.handleHTTP)
}

func TestMCPDomainInventoryLimitsConcurrentResponses(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	testInventoryResponseCapacity(t, "/api/domains", s.handleDomains)
}

func TestMCPServiceInventoryLimitsConcurrentResponses(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	testInventoryResponseCapacity(t, "/api/services", s.handleServices)
}

func TestMCPDeviceInventoryLimitsConcurrentResponses(t *testing.T) {
	s := &Server{outDir: t.TempDir()}
	testInventoryResponseCapacity(t, "/api/devices", s.handleDevices)
}

func testInventoryResponseCapacity(t *testing.T, path string, handle http.HandlerFunc) {
	t.Helper()
	testResponseCapacity(t, handle, func() *http.Request {
		return httptest.NewRequest(http.MethodGet, path+"?mcpPage=true", nil)
	})
}

func testResponseCapacity(t *testing.T, handle http.HandlerFunc, request func() *http.Request) {
	t.Helper()
	release := make(chan struct{})
	var workers sync.WaitGroup
	finish := sync.OnceFunc(func() { close(release); workers.Wait() })
	t.Cleanup(finish)
	for range 2 {
		w := heldAlertPageResponse{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}, 1), release: release}
		workers.Go(func() { handle(w, request()) })
		select {
		case <-w.writing:
			if w.Code != http.StatusOK {
				t.Fatalf("admitted request: %d", w.Code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("admitted request did not reach the response write")
		}
	}
	w := httptest.NewRecorder()
	handle(w, request())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request at capacity: %d %s", w.Code, w.Body)
	}
	finish()
	w = httptest.NewRecorder()
	handle(w, request())
	if w.Code != http.StatusOK {
		t.Fatalf("request after release: %d %s", w.Code, w.Body)
	}
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
