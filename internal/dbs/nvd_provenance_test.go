package dbs

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNVDAcquisitionBindsCountsTimestampAndInput(t *testing.T) {
	root := t.TempDir()
	year := time.Now().Year()
	path := filepath.Join(root, "nvdcve-2.0-"+strconv.Itoa(year)+".json.gz")
	writeGz(t, path, fmt.Sprintf(`{"timestamp":%q,"totalResults":10,"vulnerabilities":[]}`, time.Now().UTC().Format("2006-01-02T15:04:05.999999999")))
	sum, size, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []NVDInput{{Year: year, SHA256: sum, Size: size, URL: nvdInputURL(year)}}
	counts := map[string]int{strconv.Itoa(year): 10}
	revision, err := nvdAcquisitionRevision(root, inputs, counts)
	if err != nil {
		t.Fatal(err)
	}
	source := SourceEvidence{Revision: "fixture" + revision, NVDInputs: inputs}
	if err := validateNVDAcquisition(source, counts, 48*3600); err != nil {
		t.Fatal(err)
	}
	_, raw, _ := strings.Cut(revision, ";acquisition=")
	for _, change := range []func(*nvdAcquisition){
		func(p *nvdAcquisition) { p.DeclaredCount = 11 },
		func(p *nvdAcquisition) {
			p.FeedTimestamp = time.Now().Add(-49 * time.Hour).UTC().Format(time.RFC3339Nano)
		},
		func(p *nvdAcquisition) { p.AcquiredAt = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339Nano) },
		func(p *nvdAcquisition) { p.SHA256 = digest([]byte("changed")) },
	} {
		var observations []nvdAcquisition
		if err := json.Unmarshal([]byte(raw), &observations); err != nil {
			t.Fatal(err)
		}
		change(&observations[0])
		body, _ := json.Marshal(observations)
		bad := source
		bad.Revision = "fixture;acquisition=" + string(body)
		if err := validateNVDAcquisition(bad, counts, 48*3600); err == nil {
			t.Fatal("invalid acquisition evidence accepted")
		}
	}
	if err := os.WriteFile(path, []byte("changed source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := nvdAcquisitionRevision(root, inputs, counts); err == nil {
		t.Fatal("changed input accepted")
	}
}

func TestRefreshHealthSeparatesFailedStuckAndActive(t *testing.T) {
	dir := t.TempDir()
	if err := refreshHealth(dir); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status, stage string
		age           int64
		wantError     bool
	}{
		{"success", "complete", 0, false}, {"running", "pack", 0, false}, {"running", "acquisition", 3601, true}, {"failed", "policy", 0, true}, {"unknown", "complete", 0, true},
	} {
		if err := atomicJSON(filepath.Join(dir, "refresh-status.json"), map[string]any{"status": tc.status, "stage": tc.stage, "updated_at": time.Now().Unix() - tc.age}); err != nil {
			t.Fatal(err)
		}
		if err := refreshHealth(dir); (err != nil) != tc.wantError {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	t.Setenv("NC_DBS_SIGNED_ROOT", dir)
	if err := atomicJSON(filepath.Join(dir, "refresh-status.json"), map[string]any{"status": "failed", "stage": "policy", "updated_at": time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	NewDBServer(":0", 2002, false).Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/freshness", nil))
	if recorder.Code != 503 || !strings.Contains(recorder.Body.String(), "failed at policy") {
		t.Fatalf("refresh failure not observable by monitor: %d %s", recorder.Code, recorder.Body.String())
	}
}
