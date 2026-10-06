package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/rules"
)

func behaviorServerFixture(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	sink, err := rules.NewFileAlertWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := behavior.Open(behavior.Config{Path: filepath.Join(dir, "Behavior.json"), MinLearning: time.Second, MinSamples: 2}, sink)
	if err != nil {
		t.Fatal(err)
	}
	fact := behavior.Fact{Scope: behavior.Scope{Sensor: "fixture", Interface: "pcap"}, Kind: "device", MAC: "00:11:22:33:44:55"}
	for _, at := range []time.Time{time.Unix(1700000000, 0), time.Unix(1700000001, 0)} {
		if err := engine.Observe(at, fact); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	return &Server{outDir: dir, baseOutDir: dir}
}

func TestBehaviorAPIPersistedApprovalAndStaleVersion(t *testing.T) {
	s := behaviorServerFixture(t)
	get := httptest.NewRecorder()
	s.handleBehavior(get, httptest.NewRequest(http.MethodGet, "/api/behavior", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get = %d: %s", get.Code, get.Body)
	}
	approve := httptest.NewRecorder()
	s.handleBehaviorChange(approve, httptest.NewRequest(http.MethodPost, "/api/behavior/change", strings.NewReader(`{"action":"approve","reason":"reviewed capture","version":0}`)))
	if approve.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", approve.Code, approve.Body)
	}
	var state behavior.Snapshot
	if err := json.Unmarshal(approve.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Mode != behavior.Monitoring || state.Version != 1 || len(state.BaselineID) != 64 {
		t.Fatalf("state = %+v", state)
	}
	var id string
	for key := range state.Observed {
		id = key
	}
	body, err := json.Marshal(map[string]any{"action": "acknowledge", "ids": []string{id}, "reason": "Reviewed device evidence", "version": state.Version})
	if err != nil {
		t.Fatal(err)
	}
	ack := httptest.NewRecorder()
	s.handleBehaviorChange(ack, httptest.NewRequest(http.MethodPost, "/api/behavior/change", strings.NewReader(string(body))))
	if ack.Code != http.StatusOK {
		t.Fatalf("acknowledge = %d: %s", ack.Code, ack.Body)
	}
	stale := httptest.NewRecorder()
	s.handleBehaviorChange(stale, httptest.NewRequest(http.MethodPost, "/api/behavior/change", strings.NewReader(`{"action":"reset","reason":"stale browser","version":0}`)))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale = %d: %s", stale.Code, stale.Body)
	}
	stored, err := behavior.ReadSnapshot(filepath.Join(s.outDir, "Behavior.json"))
	if err != nil || stored.Version != 1 || stored.Mode != behavior.Monitoring {
		t.Fatalf("stale changed baseline: %+v, %v", stored, err)
	}
	if len(stored.Decisions) != 2 || stored.Decisions[1].Action != "acknowledge" || stored.Decisions[1].IDs[0] != id || len(stored.Suppressed) != 0 {
		t.Fatalf("acknowledgement not retained independently of trust: %+v", stored.Decisions)
	}
}

func TestBehaviorAPIRejectsInvalidSelectorsAndBodies(t *testing.T) {
	s := behaviorServerFixture(t)
	for _, target := range []string{"/api/behavior/change?sessionId=missing", "/api/behavior/change?inputFile=/unknown/capture.pcap"} {
		response := httptest.NewRecorder()
		s.handleBehaviorChange(response, httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"action":"reset","reason":"bad selection","version":0}`)))
		if response.Code != http.StatusNotFound {
			t.Fatalf("invalid selector = %d", response.Code)
		}
	}
	for _, body := range []string{
		`{"action":"reset","reason":"missing version"}`,
		`{"action":"reset","reason":"extra field","version":0,"unknown":true}`,
		`{"action":"reset","reason":"two objects","version":0}{}`,
	} {
		response := httptest.NewRecorder()
		s.handleBehaviorChange(response, httptest.NewRequest(http.MethodPost, "/api/behavior/change", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid body = %d: %s", response.Code, response.Body)
		}
	}
	response := httptest.NewRecorder()
	s.handleBehaviorChange(response, httptest.NewRequest(http.MethodGet, "/api/behavior/change", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mutation GET = %d", response.Code)
	}
	state, err := behavior.ReadSnapshot(filepath.Join(s.outDir, "Behavior.json"))
	if err != nil || state.Mode != behavior.Learning || state.Version != 0 {
		t.Fatal("invalid request changed baseline")
	}
}

func TestBehaviorHealthRetainedUnknownAndDeliveryMetrics(t *testing.T) {
	s := behaviorServerFixture(t)
	response := httptest.NewRecorder()
	s.handleBehaviorHealth(response, httptest.NewRequest(http.MethodGet, "/api/behavior/health", nil))
	var health behavior.Health
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &health) != nil || health.Capture != nil || health.Delivery != nil || health.Active || health.BaselineBytes == nil {
		t.Fatalf("unknown metrics: %s", response.Body)
	}
	zero := uint64(0)
	health.Capture = &behavior.CaptureHealth{KernelDrops: &zero, Packets: 10}
	health.Delivery = &behavior.DeliveryHealth{Acked: 2, Pending: 1}
	health.Active = true
	if err := behavior.WriteHealth(s.outDir, health); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	s.handleBehaviorHealth(response, httptest.NewRequest(http.MethodGet, "/api/behavior/health", nil))
	if json.Unmarshal(response.Body.Bytes(), &health) != nil || health.Active || health.Capture.KernelDrops == nil || *health.Capture.KernelDrops != 0 || health.Delivery.Pending != 1 {
		t.Fatalf("retained measured counters: %s", response.Body)
	}
	response = httptest.NewRecorder()
	s.handleBehaviorHealth(response, httptest.NewRequest(http.MethodGet, "/api/behavior/health?inputFile=unknown", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("unknown selector used active health")
	}
}

func TestBehaviorAssetContextAPISelectorsAndAddressValidation(t *testing.T) {
	s := behaviorServerFixture(t)
	response := httptest.NewRecorder()
	s.handleBehaviorAsset(response, httptest.NewRequest(http.MethodGet, "/api/behavior/asset?asset=00:11:22:33:44:55", nil))
	var context behavior.AssetContext
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &context) != nil || context.TotalRecords != 1 || context.Records[0].Direction != "unknown" {
		t.Fatalf("asset context: %d %s", response.Code, response.Body)
	}
	for target, expected := range map[string]int{"/api/behavior/asset?asset=invalid": http.StatusBadRequest, "/api/behavior/asset?asset=00:11:22:33:44:55&inputFile=unknown": http.StatusNotFound} {
		response = httptest.NewRecorder()
		s.handleBehaviorAsset(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != expected {
			t.Fatalf("selector/address: %s = %d", target, response.Code)
		}
	}
}
