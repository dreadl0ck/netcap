package webui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func serviceChildFixture(t *testing.T) (*Server, *ServiceConfig, *AnalysisJob) {
	t.Helper()
	config := &ServiceConfig{DataDir: t.TempDir(), SessionExpiry: 60, MaxAnalysisHour: 10, MaxIssueReportsPerDay: 10}
	s := NewServer("127.0.0.1:0", "", nil, "", false, false, true, config, nil, false)
	parent := filepath.Join(config.DataDir, "results", "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(config.DataDir, "source.pcap")
	if err := os.WriteFile(input, []byte("owned service input"), 0600); err != nil {
		t.Fatal(err)
	}
	s.sessionManager.AddSession(&SessionInfo{SessionID: "parent", IP: "192.0.2.1", InputFile: input, OutputDir: parent, Status: StatusCompleted})
	w := requestReanalysis(s, `{"sessionId":"parent"}`)
	if w.Code != 200 {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	job := <-s.jobQueue
	t.Cleanup(job.processingDone)
	return s, config, job
}

func TestServiceChildrenRecoverOwnershipAndTerminalState(t *testing.T) {
	for _, scenario := range []string{"completed", "failed", "interrupted", "missing-source", "changed-source", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			s, config, job := serviceChildFixture(t)
			if scenario != "failed" && scenario != "interrupted" {
				for name, value := range map[string]any{
					"capture-manifest.json":   map[string]any{"runId": job.SessionID, "status": "done", "inputSHA256": calculateFileHash(job.InputFile)},
					"audit-output-ready.json": map[string]any{"version": 1, "runId": job.SessionID},
				} {
					if err := os.WriteFile(filepath.Join(job.OutputDir, name), mustOfflineJSON(t, value), 0600); err != nil {
						t.Fatal(err)
					}
				}
				s.sessionManager.UpdateSessionStatus(job.SessionID, StatusCompleted, "", "")
			}
			if scenario == "failed" {
				s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, "decoder rejected capture", "")
			}
			if scenario == "missing-source" {
				if err := os.Remove(job.InputFile); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "changed-source" {
				if err := os.WriteFile(job.InputFile, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "expired" {
				var child childAnalysis
				data, err := os.ReadFile(filepath.Join(job.OutputDir, "analysis-parent.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &child); err != nil {
					t.Fatal(err)
				}
				child.CreatedAt = time.Now().Add(-2 * time.Hour)
				session, _ := s.sessionManager.GetSession(job.SessionID)
				session.UploadTimestamp = child.CreatedAt
				if err := writeAnalysisJSON(job.OutputDir, "analysis-parent.json", child); err != nil {
					t.Fatal(err)
				}
				if err := saveSessionMetadata(filepath.Join(job.OutputDir, "session.json"), session); err != nil {
					t.Fatal(err)
				}
			}
			restored := NewServer("127.0.0.1:0", "", nil, "", false, false, true, config, nil, false)
			child, exists := restored.sessionManager.GetSession(job.SessionID)
			if scenario == "expired" {
				if exists {
					t.Fatal("expired child was resurrected")
				}
				return
			}
			if !exists || child.IP != "192.0.2.1" || child.IsPreloaded || child.ParentSessionID != "parent" || child.InputFile != job.InputFile || len(restored.jobQueue) != 0 {
				t.Fatalf("restored child=%+v", child)
			}
			if scenario == "completed" {
				if child.Status != StatusCompleted || !child.ResultsReady {
					t.Fatal("completed child lost its witnesses")
				}
			} else {
				if child.Status != StatusFailed || child.ResultsReady || child.ErrorMessage == "" {
					t.Fatalf("invalid recovered outcome: %+v", child)
				}
				if scenario == "interrupted" && !strings.Contains(child.ErrorMessage, "interrupted") {
					t.Fatal("interruption was not qualified")
				}
			}
			r := httptest.NewRequest("GET", "/api/investigation/capture?sessionId="+job.SessionID, nil)
			r.RemoteAddr = "192.0.2.2:1234"
			if _, err := restored.resolveCaptureSelection(r); err == nil {
				t.Fatal("restoration lost private ownership")
			}
		})
	}
}

func TestSessionSnapshotsDoNotShareMutableOutcomeOrSelection(t *testing.T) {
	s, _, job := serviceChildFixture(t)
	start := int64(123)
	owned := &SessionInfo{SessionID: "snapshot", IP: "192.0.2.1", OutputDir: job.OutputDir, ParentSessionID: "parent", PacketSelection: &childPacketSelection{StartNs: &start}}
	s.sessionManager.AddSession(owned)
	owned.IP = "changed"
	start = 999
	for _, snapshot := range []*SessionInfo{func() *SessionInfo { x, _ := s.sessionManager.GetSession("snapshot"); return x }(), s.sessionManager.GetSessionsForIP("192.0.2.1")[0]} {
		snapshot.Status = StatusCompleted
		if snapshot.SessionID == "snapshot" {
			*snapshot.PacketSelection.StartNs = 888
		}
	}
	stored, _ := s.sessionManager.GetSession("snapshot")
	if stored.IP != "192.0.2.1" || *stored.PacketSelection.StartNs != 123 || stored.Status == StatusCompleted {
		t.Fatal("caller mutated owned session state")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 8 {
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusProcessing, "", "")
			s.sessionManager.UpdateSessionStatus(job.SessionID, StatusFailed, "synthetic failure", "")
		}
	}()
	go func() {
		defer wg.Done()
		for range 64 {
			for _, current := range s.sessionManager.GetAllSessions() {
				_ = current.Status
				_ = current.ErrorMessage
			}
		}
	}()
	wg.Wait()
}
