package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func restartLocalAnalysis(s *Server, input string) *Server {
	return NewServer("127.0.0.1:0", s.baseOutDir, []string{input}, "", false, false, false, nil, nil, false)
}

func admitTestChild(t *testing.T, s *Server, input string) *AnalysisJob {
	t.Helper()
	w := requestReanalysis(s, string(mustOfflineJSON(t, map[string]string{"inputFile": input})))
	if w.Code != 200 {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	job := <-s.jobQueue
	t.Cleanup(job.processingDone)
	return job
}

func completeTestChild(t *testing.T, s *Server, job *AnalysisJob) {
	t.Helper()
	child := s.childAnalyses[job.InputFile]
	for name, value := range map[string]any{
		"capture-manifest.json":   map[string]any{"runId": job.SessionID, "status": "done", "inputSHA256": child.InputSHA256},
		"audit-output-ready.json": map[string]any{"version": 1, "runId": job.SessionID},
	} {
		if err := os.WriteFile(filepath.Join(job.OutputDir, name), mustOfflineJSON(t, value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s.MarkFileCompleted(job.InputFile)
	s.SetFileProcessingTime(job.InputFile, 3.5)
}

func TestLocalChildrenRecoverAcrossRestart(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	complete := admitTestChild(t, s, input)
	completeTestChild(t, s, complete)
	failed := admitTestChild(t, s, input)
	s.SetFileError(failed.InputFile, "decoder rejected fixture", "")
	interrupted := admitTestChild(t, s, input)
	restored := restartLocalAnalysis(s, input)
	if len(restored.childAnalyses) != 3 || len(restored.jobQueue) != 0 {
		t.Fatalf("restored=%d queued=%d", len(restored.childAnalyses), len(restored.jobQueue))
	}
	if !restored.completedFiles[complete.InputFile] || restored.fileProcessingTime[complete.InputFile] != 3.5 {
		t.Fatal("completed child lost durable state")
	}
	if restored.fileErrors[failed.InputFile].Error != "decoder rejected fixture" {
		t.Fatal("failed child lost its outcome")
	}
	if !strings.Contains(restored.fileErrors[interrupted.InputFile].Error, "interrupted") || restored.completedFiles[interrupted.InputFile] {
		t.Fatal("interrupted child became completed")
	}
	for _, job := range []*AnalysisJob{complete, failed, interrupted} {
		if restored.fileIDToPath[job.SessionID] != job.InputFile || restored.fileOutputDirs[job.InputFile] != job.OutputDir {
			t.Fatalf("child rebound after restart: %+v", job)
		}
	}
}

func TestChildRecoveryMissingOrChangedSourceRemainsVisible(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "changed"}[missing], func(t *testing.T) {
			s, input, _ := reanalysisFixture(t)
			job := admitTestChild(t, s, input)
			completeTestChild(t, s, job)
			if missing {
				if err := os.Remove(job.InputFile); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(job.InputFile, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			restored := restartLocalAnalysis(s, input)
			if restored.completedFiles[job.InputFile] || restored.fileErrors[job.InputFile].Error == "" {
				t.Fatal("unavailable source became healthy")
			}
			w := httptest.NewRecorder()
			restored.handleInputFiles(w, httptest.NewRequest(http.MethodGet, "/api/files/input", nil))
			var files []FileInfo
			if err := json.Unmarshal(w.Body.Bytes(), &files); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, file := range files {
				if file.ID == job.SessionID {
					found = file.Error != nil && !file.IsCompleted
				}
			}
			if !found {
				t.Fatalf("failed child disappeared: %s", w.Body.String())
			}
		})
	}
}

func TestChildRecoveryRejectsEscapesAndCorruptMetadata(t *testing.T) {
	for _, scenario := range []string{"source-symlink", "output-symlink", "outside-parent", "corrupt-metadata", "id-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			s, input, _ := reanalysisFixture(t)
			job := admitTestChild(t, s, input)
			metadata := filepath.Join(job.OutputDir, "analysis-parent.json")
			switch scenario {
			case "source-symlink":
				if err := os.Remove(job.InputFile); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(input, job.InputFile); err != nil {
					t.Fatal(err)
				}
			case "output-symlink":
				external := t.TempDir()
				moved := filepath.Join(external, "owned")
				if err := os.Rename(job.OutputDir, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(moved, job.OutputDir); err != nil {
					t.Fatal(err)
				}
			case "outside-parent", "id-mismatch":
				child := s.childAnalyses[job.InputFile]
				if scenario == "outside-parent" {
					child.ParentOutputDir = t.TempDir()
					child.AnalysisRoot = ""
				} else {
					child.AnalysisID = "analysis-other"
				}
				if err := os.WriteFile(metadata, mustOfflineJSON(t, child), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-metadata":
				if err := os.WriteFile(metadata, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			restored := restartLocalAnalysis(s, input)
			if len(restored.childAnalyses) != 0 {
				t.Fatal("invalid child was restored")
			}
		})
	}
}

func TestChildCompletionRequiresDurableAuditWitness(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	job := admitTestChild(t, s, input)
	// A completion flag alone cannot establish that audit output was finalized.
	s.MarkFileCompleted(job.InputFile)
	restored := restartLocalAnalysis(s, input)
	if restored.completedFiles[job.InputFile] || restored.fileErrors[job.InputFile].Error == "" {
		t.Fatal("unwitnessed output became completed")
	}
}

func TestChildStateWriteFailureDoesNotReportCompletion(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	job := admitTestChild(t, s, input)
	if err := os.Mkdir(filepath.Join(job.OutputDir, "analysis-state.json-block"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(job.OutputDir, "analysis-state.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(job.OutputDir, "analysis-state.json-block"), filepath.Join(job.OutputDir, "analysis-state.json")); err != nil {
		t.Fatal(err)
	}
	s.MarkFileCompleted(job.InputFile)
	if s.completedFiles[job.InputFile] || !strings.Contains(s.fileErrors[job.InputFile].Error, "persist child completion") {
		t.Fatal("failed durable write became success")
	}
}

func TestChildRecoveryRejectsDuplicateIDs(t *testing.T) {
	s, input, _ := reanalysisFixture(t)
	job := admitTestChild(t, s, input)
	// The configured output itself may be a parent output, with children beside it.
	s.baseOutDir = filepath.Join(s.baseOutDir, "nested")
	if err := os.Mkdir(s.baseOutDir, 0700); err != nil {
		t.Fatal(err)
	}
	duplicate := filepath.Join(s.baseOutDir, job.SessionID)
	if err := os.CopyFS(duplicate, os.DirFS(job.OutputDir)); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{job.OutputDir, duplicate} {
		child := s.childAnalyses[job.InputFile]
		child.ParentOutputDir = s.baseOutDir
		if err := os.WriteFile(filepath.Join(dir, "analysis-parent.json"), mustOfflineJSON(t, child), 0600); err != nil {
			t.Fatal(err)
		}
	}
	restored := restartLocalAnalysis(s, input)
	if len(restored.childAnalyses) != 0 {
		t.Fatal("duplicate IDs arbitrarily rebound a child")
	}
}

func TestRootBoundGrandchildSurvivesRemovalOfItsParent(t *testing.T) {
	s, input, parent := reanalysisFixture(t)
	s.baseOutDir = parent
	first := admitTestChild(t, s, input)
	completeTestChild(t, s, first)
	second := admitTestChild(t, s, first.InputFile)
	completeTestChild(t, s, second)
	if err := os.RemoveAll(first.OutputDir); err != nil {
		t.Fatal(err)
	}
	restored := restartLocalAnalysis(s, input)
	if !restored.completedFiles[second.InputFile] || restored.fileIDToPath[second.SessionID] != second.InputFile {
		t.Fatal("retained grandchild depended on its parent's directory lifetime")
	}
}
