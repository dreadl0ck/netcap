package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/evidencelink"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func writeEvidenceFixture(t *testing.T, dir string, typ types.Type, name string, records ...proto.Message) {
	t.Helper()
	w := netio.NewAuditRecordWriter(&netio.WriterConfig{Proto: true, Name: name, Buffer: true, Compress: true, Out: dir,
		MemBufferSize: defaults.BufferSize, Source: "test", Version: netcap.Version, StartTime: time.Unix(0, 1), CompressionBlockSize: defaults.CompressionBlockSize})
	if err := w.WriteHeader(typ); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	w.Close(int64(len(records)))
}

func TestEvidenceRelatedEndpointHonoursFeatureToggle(t *testing.T) {
	dir := t.TempDir()
	const cid = "1:aaaaaaaaaaaaaaaaaaaaaaaaaaa="
	writeEvidenceFixture(t, dir, types.Type_NC_Connection, "Connection",
		&types.Connection{TimestampFirst: 10, TimestampLast: 20, SrcIP: "10.0.0.5", DstIP: "192.0.2.1", CommunityID: cid, ObservationID: "obs", SnapshotSequence: 1})
	writeEvidenceFixture(t, dir, types.Type_NC_HTTP, "HTTP", &types.HTTP{Timestamp: 15, Method: "GET", CommunityID: cid})
	config := evidencelink.DefaultConfig()
	s := &Server{outDir: dir, baseOutDir: dir, features: newFeatureSet(nil), runtimeConfig: &RuntimeConfig{EvidenceLinks: &config}}

	get := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleEvidenceRelated(w, httptest.NewRequest(http.MethodGet, "/api/evidence/related?"+query, nil))
		return w
	}
	w := get("observationId=obs")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var result evidencelink.Result
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Links) != 1 || result.Links[0].Record.Type != "HTTP" {
		t.Fatalf("result = %+v (%v)", result, err)
	}
	if w := get("type=HTTP&communityId=" + strings.ReplaceAll(cid, "=", "%3D") + "&time=15"); w.Code != http.StatusOK {
		t.Fatalf("community selector status %d: %s", w.Code, w.Body)
	}
	if w := get("type=HTTP&ordinal=9"); w.Code != http.StatusNotFound {
		t.Fatalf("missing record status %d", w.Code)
	}
	if w := get("type=../x&ordinal=0"); w.Code != http.StatusBadRequest {
		t.Fatalf("path type status %d", w.Code)
	}
	if w := get("ordinal=0"); w.Code != http.StatusBadRequest {
		t.Fatalf("incomplete selector status %d", w.Code)
	}

	toggle := httptest.NewRecorder()
	s.handleFeatures(toggle, httptest.NewRequest(http.MethodPost, "/api/features", strings.NewReader(`{"name":"evidence-links","enabled":false}`)))
	if toggle.Code != http.StatusOK || s.featureEnabled(featureEvidenceLinks) || !s.featureEnabled(featureNetworkDetection) {
		t.Fatalf("toggle failed: %d %s", toggle.Code, toggle.Body)
	}
	if w := get("observationId=obs"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled status %d: %s", w.Code, w.Body)
	}
	for _, body := range []string{`{"name":"nope","enabled":true}`, `{"name":"evidence-links"}`, `{"name":"evidence-links","enabled":true,"x":1}`} {
		w := httptest.NewRecorder()
		s.handleFeatures(w, httptest.NewRequest(http.MethodPost, "/api/features", strings.NewReader(body)))
		if w.Code == http.StatusOK {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestFeaturesStartupStateComesFromFlags(t *testing.T) {
	f := newFeatureSet(map[string]bool{featureNetworkDetection: false})
	if f.Enabled(featureNetworkDetection) || !f.Enabled(featureEvidenceLinks) {
		t.Fatalf("startup state: %+v", f.List())
	}
}
