package webui

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/gopacket/gopacket/pcapgo"
)

func subsetFixture(t *testing.T) (*Server, string, string, *childPacketSelection) {
	t.Helper()
	s, input, parent := reanalysisFixture(t)
	path, base := observedTuplePCAP(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := calculateFileHash(input)
	if err := os.WriteFile(filepath.Join(parent, "capture-manifest.json"), mustOfflineJSON(t, map[string]any{"runId": "parent-run", "status": "done", "inputSHA256": hash}), 0600); err != nil {
		t.Fatal(err)
	}
	start, end := base.Add(time.Nanosecond).UnixNano(), base.Add(2*time.Nanosecond).UnixNano()
	selection := &childPacketSelection{Version: 1, SourceSHA256: hash,
		BPF:     "tcp and ((src host 192.0.2.1 and src port 52123 and dst host 198.51.100.1 and dst port 9243) or (src host 198.51.100.1 and src port 9243 and dst host 192.0.2.1 and dst port 52123))",
		StartNs: &start, EndNs: &end}
	return s, input, parent, selection
}

func subsetRequestBody(t *testing.T, input, run string, selection *childPacketSelection) string {
	t.Helper()
	return string(mustOfflineJSON(t, map[string]any{"inputFile": input, "runId": run, "selection": selection}))
}

func TestSubsetChildRetainsExactSelectionAndSurvivesRestart(t *testing.T) {
	s, input, parent, selection := subsetFixture(t)
	w := requestReanalysis(s, subsetRequestBody(t, input, "parent-run", selection))
	if w.Code != 200 {
		t.Fatalf("subset: %d %s", w.Code, w.Body.String())
	}
	job := <-s.jobQueue
	defer job.processingDone()
	if filepath.Base(job.InputFile) != "selected.pcapng" || job.OutputDir == parent {
		t.Fatal("subset did not get its own source and output")
	}
	var manifest evidence.PacketManifest
	data, err := os.ReadFile(filepath.Join(job.OutputDir, "packet-selection.json"))
	if err != nil || json.Unmarshal(data, &manifest) != nil {
		t.Fatalf("manifest=%s %v", data, err)
	}
	if manifest.SourcePackets != 6 || manifest.Selected != 2 || manifest.SourceSHA256 != selection.SourceSHA256 || manifest.OutputSHA256 != calculateFileHash(job.InputFile) || len(manifest.PacketSpans) != 1 || manifest.PacketSpans[0] != (evidence.PacketSpan{First: 2, Last: 3}) || len(manifest.Interfaces) != 1 {
		t.Fatalf("incorrect selection witness: %+v", manifest)
	}
	f, err := os.Open(job.InputFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []int64{*selection.StartNs, *selection.EndNs} {
		_, info, err := reader.ReadPacketData()
		if err != nil || info.Timestamp.UnixNano() != expected {
			t.Fatalf("timestamp=%v err=%v", info.Timestamp, err)
		}
	}
	if _, _, err := reader.ReadPacketData(); err != io.EOF {
		t.Fatal("subset includes negative tuple/transport controls")
	}
	child := s.childAnalyses[job.InputFile]
	if child.Selector != "packet-subset" || child.PacketSelection == nil || child.InputSHA256 != manifest.OutputSHA256 || child.PacketSelection.SourceSHA256 != manifest.SourceSHA256 {
		t.Fatal("child lost source/derivative distinction")
	}
	completeTestChild(t, s, job)
	restored := restartLocalAnalysis(s, input)
	if !restored.completedFiles[job.InputFile] || restored.fileIDToPath[job.SessionID] != job.InputFile {
		t.Fatal("subset child was not recovered")
	}
	listed := httptest.NewRecorder()
	restored.handleInputFiles(listed, httptest.NewRequest("GET", "/api/files/input", nil))
	var files []FileInfo
	if err := json.Unmarshal(listed.Body.Bytes(), &files); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		if file.ID == job.SessionID {
			found = file.AnalysisSelector == "packet-subset" && file.ParentRunID == "parent-run" && file.PacketSelection != nil && file.PacketSelection.BPF == selection.BPF
		}
	}
	if !found {
		t.Fatal("reopened child lost its API selection context")
	}
	assertParentPreserved(t, s, input, parent)
}

func TestSubsetChildRejectsUnqualifiedAndFailedPreparation(t *testing.T) {
	for _, scenario := range []string{"missing-run", "stale-run", "missing-hash", "wrong-hash", "version", "one-bound", "invalid-bpf", "empty", "packet-limit", "byte-limit", "source-changed", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			s, input, parent, selection := subsetFixture(t)
			run, want := "parent-run", 400
			switch scenario {
			case "missing-run":
				run = ""
			case "stale-run":
				run, want = "older-run", 409
			case "missing-hash":
				selection.SourceSHA256 = ""
			case "wrong-hash":
				selection.SourceSHA256, want = strings.Repeat("a", 64), 409
			case "version":
				selection.Version = 2
			case "one-bound":
				selection.EndNs = nil
			case "invalid-bpf":
				selection.BPF = "not valid ((("
			case "empty":
				selection.BPF, want = "host 203.0.113.250", 422
			case "packet-limit":
				selection.MaxPackets, want = 1, 413
			case "byte-limit":
				selection.MaxOutputBytes, want = 1, 413
			case "source-changed":
				data, err := os.ReadFile(input)
				if err != nil {
					t.Fatal(err)
				}
				data[len(data)-1] ^= 1
				if err := os.WriteFile(input, data, 0600); err != nil {
					t.Fatal(err)
				}
				want = 409
			case "canceled":
				want = 408
			}
			body := subsetRequestBody(t, input, run, selection)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/reanalyze", strings.NewReader(body))
			if scenario == "canceled" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			s.handleReanalyze(w, r)
			if w.Code != want || len(s.jobQueue) != 0 || len(s.childAnalyses) != 0 {
				t.Fatalf("%d want=%d %s", w.Code, want, w.Body.String())
			}
			entries, err := os.ReadDir(filepath.Dir(parent))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "analysis-") {
					t.Fatal("failed preparation retained an unregistered child")
				}
			}
			assertParentPreserved(t, s, input, parent)
		})
	}
}

func TestSubsetRecoveryRequiresUnchangedSelectionManifest(t *testing.T) {
	s, input, _, selection := subsetFixture(t)
	w := requestReanalysis(s, subsetRequestBody(t, input, "parent-run", selection))
	if w.Code != 200 {
		t.Fatalf("admission: %d %s", w.Code, w.Body.String())
	}
	job := <-s.jobQueue
	defer job.processingDone()
	completeTestChild(t, s, job)
	if err := os.WriteFile(filepath.Join(job.OutputDir, "packet-selection.json"), []byte(`{"selectedPackets":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	restored := restartLocalAnalysis(s, input)
	if restored.completedFiles[job.InputFile] || !strings.Contains(restored.fileErrors[job.InputFile].Error, "selection manifest") {
		t.Fatal("changed subset witness became healthy")
	}
}

func TestReanalysisRejectsMisspelledOrTrailingSelection(t *testing.T) {
	s, input, _, _ := subsetFixture(t)
	for _, body := range []string{
		string(mustOfflineJSON(t, map[string]any{"inputFile": input, "selecton": map[string]any{"bpf": "tcp"}})),
		string(mustOfflineJSON(t, map[string]any{"inputFile": input, "selection": map[string]any{"version": 1, "start_ns": "123"}})),
		string(mustOfflineJSON(t, map[string]any{"inputFile": input})) + " {}",
	} {
		w := requestReanalysis(s, body)
		if w.Code != 400 || len(s.jobQueue) != 0 {
			t.Fatalf("unrecognized selection queued whole input: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestSubsetTimeOnlySelectionKeepsAllMatchingTransports(t *testing.T) {
	s, input, _, selection := subsetFixture(t)
	selection.BPF = ""
	w := requestReanalysis(s, subsetRequestBody(t, input, "parent-run", selection))
	if w.Code != 200 {
		t.Fatalf("time-only selection: %d %s", w.Code, w.Body.String())
	}
	job := <-s.jobQueue
	defer job.processingDone()
	var manifest evidence.PacketManifest
	if err := readEvidenceJSON(filepath.Join(job.OutputDir, "packet-selection.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Selected != 5 {
		t.Fatalf("time-only selection invented transport filtering: %+v", manifest)
	}
}
