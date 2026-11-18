package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func partialAuditFixture(t *testing.T, service bool) (http.Handler, string, string, string) {
	t.Helper()
	directory := t.TempDir()
	file := writeTimelineAuditFile(t, directory, "Connection", types.Type_NC_Connection, []proto.Message{&types.Connection{SrcIP: "192.0.2.1"}, &types.Connection{SrcIP: "192.0.2.2"}})
	capture, err := evidence.NewCapture(context.Background(), directory, evidence.CaptureConfig{Kind: "live", Source: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	capture.CoverageError(errors.New("partial input"))
	if err := capture.Close("partial", 2, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := capture.SealAuditStages([]evidence.AuditStage{{Type: "Connection", Stage: "aggregate", State: "sealed", Coverage: "partial", Reason: "partial input", Records: 2, Files: []evidence.SealedAuditFile{{Name: filepath.Base(file)}}}, {Type: "TCP", Stage: "packet", State: "sealed", Coverage: "partial"}, {Type: "HTTP", Stage: "application", State: "failed", Coverage: "partial", Reason: "parser pressure"}}); err != nil {
		t.Fatal(err)
	}
	_, snapshot, err := evidence.ReadAuditStage(directory, capture.RunID(), "Connection", "")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{outDir: directory, activeInputFile: "input", inputFiles: []string{"input"}, fileOutputDirs: map[string]string{"input": directory}, fileIDToPath: map[string]string{"owned": "input"}, fileErrors: map[string]FileError{"input": {Error: "analysis incomplete"}}}
	if service {
		s.isServiceMode = true
		s.sessionManager = NewSessionManager(10, 60, 10)
		s.sessionManager.AddSession(&SessionInfo{SessionID: "owned", InputFile: "input", OutputDir: directory, Status: StatusFailed, ErrorMessage: "analysis incomplete", IsPreloaded: true})
	}
	handler := s.captureSelectionMiddleware(http.HandlerFunc(s.handleAuditRecords))
	return handler, capture.RunID(), snapshot.Generation, file
}

func TestPartialAuditReaderRejectsReplacementAfterAdmission(t *testing.T) {
	for _, replacement := range []string{"link", "larger"} {
		t.Run(replacement, func(t *testing.T) {
			_, run, _, file := partialAuditFixture(t, false)
			r := httptest.NewRequest("GET", "/api/audit/Connection/stream?sessionId=owned&allowPartial=true", nil)
			sealed, err := preparePartialAudit(r, captureSelection{RunID: run, OutputDir: filepath.Dir(file)})
			if err != nil {
				t.Fatal(err)
			}
			if replacement == "link" {
				if err := os.Rename(file, file+".other"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(file)+".other", file); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Truncate(file, sealed.Stage.Files[0].Size+1); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			HandleAuditStream(w, withPartialAudit(r, sealed), file, "Connection")
			if body := w.Body.String(); !strings.Contains(body, "event: error\n") || strings.Contains(body, "event: record\n") || strings.Contains(body, "event: complete\n") {
				t.Fatalf("replacement admitted into audit stream: %s", body)
			}
		})
	}
}

func TestPartialAuditAdmissionRequiresSealedExplicitQualifiedOutput(t *testing.T) {
	for _, service := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "service"}[service], func(t *testing.T) {
			handler, run, generation, file := partialAuditFixture(t, service)
			first := httptest.NewRecorder()
			const firstPath = "/api/audit/Connection/stream?sessionId=owned&allowPartial=true&limit=1"
			handler.ServeHTTP(first, httptest.NewRequest("GET", firstPath, nil))
			_, completion, _ := strings.Cut(first.Body.String(), "event: complete\ndata: ")
			var summary struct{ QueryGeneration string }
			if err := json.Unmarshal([]byte(completion), &summary); err != nil || summary.QueryGeneration == "" {
				t.Fatalf("missing query generation: %v, %s", err, first.Body)
			}
			next := "sessionId=owned&allowPartial=true&offset=1&runId=" + run + "&stageGeneration=" + generation + "&queryGeneration=" + summary.QueryGeneration
			func() {
				for range 2 {
					select {
					case sealedAuditVerificationSlots <- struct{}{}:
						defer func() { <-sealedAuditVerificationSlots }()
					default:
						t.Fatal("expected two available verification slots")
					}
				}
				for _, tc := range []struct {
					query string
					want  int
				}{{next, 429}, {next + "&fields=SrcIP", 409}} {
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/audit/Connection/stream?"+tc.query, nil))
					if w.Code != tc.want {
						t.Fatalf("saturated verification: got %d, want %d: %s", w.Code, tc.want, w.Body)
					}
				}
				// An initial page with no resolved run must acquire a slot before opening its manifest.
				r := httptest.NewRequest("GET", firstPath, nil)
				_, err := preparePartialAudit(r, captureSelection{OutputDir: t.TempDir()})
				w := httptest.NewRecorder()
				writeSelectionError(w, err)
				if w.Code != 429 {
					t.Fatalf("initial page bypassed manifest admission: %d %s", w.Code, w.Body)
				}
			}()
			for _, tc := range []struct {
				path, query string
				status      int
				records     int
			}{
				{"Connection", "sessionId=owned", 422, 0},
				{"Connection", "sessionId=owned&allowPartial=false", 422, 0},
				{"Connection", "allowPartial=true", 400, 0},
				{"Connection", "sessionId=owned&allowPartial=true&allowPartial=false", 400, 0},
				{"Connection", "sessionId=owned&allowPartial=true&limit=1", 200, 1},
				{"Connection", "sessionId=owned&allowPartial=true&offset=1", 409, 0},
				{"Connection", next, 200, 1},
				{"Connection", next + "&filter=true", 409, 0},
				{"Connection", next + "&fields=SrcIP", 409, 0},
				{"TCP", next, 409, 0},
				{"Connection", "sessionId=owned&allowPartial=true&stageGeneration=stale", 422, 0},
				{"Connection", "sessionId=owned&allowPartial=true&runId=stale", 409, 0},
				{"TCP", "sessionId=owned&allowPartial=true", 200, 0},
				{"HTTP", "sessionId=owned&allowPartial=true", 422, 0},
			} {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/audit/"+tc.path+"/stream?"+tc.query, nil))
				if response.Code != tc.status {
					t.Fatalf("%s: status %d want %d: %s", tc.query, response.Code, tc.status, response.Body.String())
				}
				if tc.status == 200 {
					body := response.Body.String()
					if strings.Count(body, "event: record\n") != tc.records || !strings.Contains(body, `"coverage":"partial"`) || !strings.Contains(body, `"stageGeneration":"`+generation+`"`) || !strings.Contains(body, `"runId":"`+run+`"`) || strings.Contains(body, "event: error") {
						t.Fatal("partial output lost coverage/generation", body)
					}
				}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/secrets?sessionId=owned&allowPartial=true", nil))
			if response.Code != 400 {
				t.Fatal("partial opt-in bypassed unrelated route admission", response.Code)
			}
			if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/audit/Connection/stream?"+next+"&fields=SrcIP", nil))
			if response.Code != 409 {
				t.Fatalf("changed projection should be rejected before verifying the audit file: %d %s", response.Code, response.Body.String())
			}
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/audit/Connection/stream?sessionId=owned&allowPartial=true&runId="+url.QueryEscape(run), nil))
			if response.Code != 422 {
				t.Fatal("changed audit file was readable", response.Code, response.Body.String())
			}
		})
	}
}
