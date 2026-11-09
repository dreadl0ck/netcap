package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/internal/artifactio"
)

type reproductionSource struct {
	SHA256                 string
	Bytes                  int64
	PreviousManifestSHA256 string
}

type failedReproduction struct {
	Source      reproductionSource
	FailureHash string
	Settings    map[string]any
	OutputDir   string
}

func priorReproductionManifest(dir string) string {
	if dir == "" {
		return ""
	}
	data, err := artifactio.Read(context.Background(), dir, "capture-manifest.json", 4<<20)
	if err != nil {
		return ""
	}
	return digestBytes(data)
}

// Capture the admitted bytes before a helper can fail or the input can change.
func snapshotReproductionSource(path string) reproductionSource {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return reproductionSource{}
	}
	f, err := os.Open(path)
	if err != nil {
		return reproductionSource{}
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return reproductionSource{}
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, opened.Size()+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || n != opened.Size() || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() {
		return reproductionSource{}
	}
	return reproductionSource{SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: n}
}

func failureReproductionKey(service bool, session, input string) string {
	if service {
		return "session:" + session
	}
	return "input:" + input
}

func reproductionSourceConflict(selected captureSelection, hash string) bool {
	return selected.SessionID == "" && validHexIdentity(selected.AnalysisID, 32) && selected.AnalysisID != hash
}

func (s *Server) rememberFailedReproduction(job *AnalysisJob, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failedReproductions == nil {
		s.failedReproductions = make(map[string]failedReproduction)
	}
	key := failureReproductionKey(s.isServiceMode, job.SessionID, job.InputFile)
	s.failedReproductions[key] = failedReproduction{
		Source: job.reproductionSource, FailureHash: digestBytes([]byte(message)), OutputDir: job.OutputDir,
		Settings: map[string]any{"dpiRequested": job.EnableDPI, "bpfSHA256": digestBytes([]byte(job.BPFFilter)), "includeDecodersSHA256": digestBytes([]byte(job.IncludeDecoders)), "excludeDecodersSHA256": digestBytes([]byte(job.ExcludeDecoders)), "artifactConfigSHA256": digestBytes(job.ArtifactConfig)},
	}
	if !s.isServiceMode && job.OutputDir != "" {
		if s.fileOutputDirs == nil {
			s.fileOutputDirs = make(map[string]string)
		}
		// Retain the failed job's directory without changing the active capture.
		s.fileOutputDirs[job.InputFile] = job.OutputDir
	}
}

func (s *Server) failedReproductionFor(selected captureSelection) (failedReproduction, bool) {
	s.mu.RLock()
	service, manager := s.isServiceMode, s.sessionManager
	failure, exists := s.failedReproductions[failureReproductionKey(service, selected.SessionID, selected.InputFile)]
	fileError, localFailed := s.fileErrors[selected.InputFile]
	s.mu.RUnlock()
	if !exists {
		return failure, false
	}
	if service {
		if manager == nil {
			return failure, false
		}
		manager.mu.RLock()
		session, found := manager.sessions[selected.SessionID]
		failed := found && session.Status == StatusFailed
		manager.mu.RUnlock()
		if !failed {
			return failure, false
		}
	} else if !localFailed || digestBytes([]byte(fileError.Error)) != failure.FailureHash {
		return failure, false
	}
	return failure, true
}

func (s *Server) writeFailedReproduction(w http.ResponseWriter, r *http.Request, selected captureSelection, manifestState string) bool {
	failure, exists := s.failedReproductionFor(selected)
	if !exists {
		return false
	}
	if reproductionSourceConflict(selected, failure.Source.SHA256) {
		http.Error(w, "Analysis source identity is stale", http.StatusConflict)
		return true
	}
	if selected.RunID != "" {
		http.Error(w, "Capture generation is unavailable or stale", http.StatusConflict)
		return true
	}
	if !validHexIdentity(failure.Source.SHA256, 32) {
		http.Error(w, "Admitted source identity unavailable; reproduction metadata cannot be bound safely", http.StatusConflict)
		return true
	}
	if r.URL.Query().Get("reviewedLog") == "true" {
		http.Error(w, "Reviewed log projection requires a capture manifest", http.StatusConflict)
		return true
	}
	bundle := map[string]any{
		"schema": "netcap-reproduction-metadata/v1", "state": "metadata-only", "metadataBasis": "failed-job-admission",
		"exporter": map[string]string{"version": netcap.Version, "commit": netcap.Commit}, "producerVersion": "unavailable", "runId": "unavailable", "captureStatus": "error",
		"sourceSHA256": failure.Source.SHA256, "sourceBytes": strconv.FormatInt(failure.Source.Bytes, 10), "sourceBinding": "server-admission-snapshot",
		"failureSHA256": failure.FailureHash, "requestedSettings": failure.Settings,
		"effectiveSettings": map[string]string{"state": "unavailable", "reason": "capture-manifest-" + manifestState},
		"attachments":       []reproductionAttachment{{Name: "capture-manifest.json", State: manifestState}, {Name: "audit-output-ready.json", State: "unavailable"}, {Name: "logs-and-payloads", State: "omitted-sensitive"}},
		"limitations":       []string{"Current analysis failed before bound capture metadata was available; this is a server job-admission snapshot, not a fabricated capture manifest", "Source digest identifies admitted bytes, not proof of which bytes a failed producer processed", "Producer identity, run ID and effective settings are unavailable without a current capture manifest", "Requested setting digests do not establish effective producer settings", "No source paths, raw logs, payloads or free-text errors are attached"},
	}
	w.Header().Set("Content-Disposition", `attachment; filename="netcap-reproduction-metadata.json"`)
	RespondJSON(w, http.StatusOK, bundle)
	return true
}
