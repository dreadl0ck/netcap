package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

type childAnalysis struct {
	Version              int       `json:"version"`
	AnalysisID           string    `json:"analysisId"`
	CreatedAt            time.Time `json:"createdAt"`
	EngineVersion        string    `json:"engineVersion"`
	EngineCommit         string    `json:"engineCommit"`
	Selector             string    `json:"selector"`
	ParentSessionID      string    `json:"parentSessionId,omitempty"`
	ParentInputFile      string    `json:"parentInputFile"`
	ParentOutputDir      string    `json:"parentOutputDir"`
	ParentRunID          string    `json:"parentRunId,omitempty"`
	ParentManifestSHA256 string    `json:"parentManifestSHA256,omitempty"`
	InputSHA256          string    `json:"inputSHA256"`
	EnableDPI            bool      `json:"enableDPI"`
	BPFFilter            string    `json:"bpfFilter"`
	ArtifactConfig       []byte    `json:"artifactConfig"`
}

// Copy the input so parent expiry or replacement cannot change a queued child's source.
func snapshotAnalysisInput(source, destination string) (string, int64, error) {
	in, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("analysis input must be a regular file")
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, hash), in)
	closeErr := out.Close()
	if copyErr != nil {
		return "", n, copyErr
	}
	if closeErr != nil {
		return "", n, closeErr
	}
	after, err := in.Stat()
	if err != nil {
		return "", n, err
	}
	if n != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", n, fmt.Errorf("analysis input changed during snapshot")
	}
	return hex.EncodeToString(hash.Sum(nil)), n, nil
}

func (s *Server) queueChildAnalysis(w http.ResponseWriter, input, parentDir, parentSession, ip string) {
	if s.jobQueue == nil {
		http.Error(w, errAnalysisUnavailable.Error(), http.StatusServiceUnavailable)
		return
	}
	config, err := snapshotArtifactConfig()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.RLock()
	enableDPI := s.dpiConfigured
	s.mu.RUnlock()
	provenance := childAnalysis{Version: 1, CreatedAt: time.Now().UTC(), ParentSessionID: parentSession,
		EngineVersion: netcap.Version, EngineCommit: netcap.Commit, Selector: "whole-capture",
		ParentInputFile: input, ParentOutputDir: parentDir, EnableDPI: enableDPI,
		BPFFilter: s.loadBPFConfig().Filter, ArtifactConfig: config}
	var parent evidence.CaptureManifest
	if data, readErr := os.ReadFile(filepath.Join(parentDir, "capture-manifest.json")); readErr == nil {
		if err := json.Unmarshal(data, &parent); err != nil {
			http.Error(w, "Invalid parent capture manifest", http.StatusConflict)
			return
		}
		hash := sha256.Sum256(data)
		provenance.ParentManifestSHA256 = hex.EncodeToString(hash[:])
		provenance.ParentRunID = parent.RunID
	} else if !os.IsNotExist(readErr) {
		http.Error(w, readErr.Error(), http.StatusInternalServerError)
		return
	}
	dir, err := os.MkdirTemp(filepath.Dir(parentDir), "analysis-")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	registered := false
	defer func() {
		if !registered {
			os.RemoveAll(dir)
		}
	}()
	provenance.AnalysisID = filepath.Base(dir)
	if err := os.Mkdir(filepath.Join(dir, "source"), 0700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	childInput := filepath.Join(dir, "source", filepath.Base(input))
	hash, size, err := snapshotAnalysisInput(input, childInput)
	if err != nil {
		code := http.StatusInternalServerError
		if os.IsNotExist(err) {
			code = http.StatusNotFound
		}
		http.Error(w, err.Error(), code)
		return
	}
	if parent.InputSHA256 != "" && parent.InputSHA256 != hash {
		http.Error(w, "Input no longer matches parent capture hash", http.StatusConflict)
		return
	}
	provenance.InputSHA256 = hash
	metadata, err := json.MarshalIndent(provenance, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "analysis-parent.json"), metadata, 0600)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	job := &AnalysisJob{SessionID: provenance.AnalysisID, InputFile: childInput, OutputDir: dir,
		EnableDPI: enableDPI, BPFFilter: provenance.BPFFilter, ArtifactConfig: config}
	if s.sessionManager != nil {
		child := &SessionInfo{SessionID: job.SessionID, IP: ip, UploadTimestamp: provenance.CreatedAt,
			InputFile: childInput, InputFilename: filepath.Base(input), InputFileSize: size, OutputDir: dir,
			Status: StatusQueued, ShareUrl: "/view/" + job.SessionID, BPFFilter: job.BPFFilter,
			ParentSessionID: parentSession}
		if err := saveSessionMetadata(filepath.Join(dir, "session.json"), child); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.sessionManager.AddSession(child)
	} else {
		if err := writeChildState(dir, localChildState{Version: 1, Status: StatusQueued}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		if s.childAnalyses == nil {
			s.childAnalyses = make(map[string]childAnalysis)
		}
		if s.fileIDToPath == nil {
			s.fileIDToPath = make(map[string]string)
		}
		if s.fileOutputDirs == nil {
			s.fileOutputDirs = make(map[string]string)
		}
		if s.fileBPFFilters == nil {
			s.fileBPFFilters = make(map[string]string)
		}
		s.childAnalyses[childInput] = provenance
		s.fileIDToPath[job.SessionID] = childInput
		s.fileOutputDirs[childInput] = dir
		s.fileBPFFilters[childInput] = job.BPFFilter
		s.inputFiles = append(s.inputFiles, childInput)
		s.mu.Unlock()
	}
	registered = true
	if err := s.enqueueAnalysis(job, false); err != nil {
		s.recordAnalysisFailure(job, err.Error(), "")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"success": true, "message": "Child analysis queued successfully",
		"sessionId": job.SessionID, "id": job.SessionID, "path": childInput, "filename": filepath.Base(input),
		"parentSessionId": parentSession, "parentInputFile": input})
}
