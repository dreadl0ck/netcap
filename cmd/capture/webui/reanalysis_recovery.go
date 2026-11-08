package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/rules"
)

type localChildState struct {
	Version        int           `json:"version"`
	Status         SessionStatus `json:"status"`
	Error          string        `json:"error,omitempty"`
	ErrorLog       string        `json:"errorLog,omitempty"`
	ProcessingTime float64       `json:"processingTime,omitempty"`
}

func writeChildState(dir string, state localChildState) error {
	return writeAnalysisJSON(dir, "analysis-state.json", state)
}

func writeAnalysisJSON(dir, destination string, value any) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := ".analysis-state-" + generateSessionID()
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	writeErr := json.NewEncoder(f).Encode(value)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(name, destination)
}

func (s *Server) saveLocalChildStateLocked(input string) error {
	if _, child := s.childAnalyses[input]; !child {
		return nil
	}
	state := localChildState{Version: 1, Status: StatusQueued, ProcessingTime: s.fileProcessingTime[input]}
	if s.completedFiles[input] {
		state.Status = StatusCompleted
	}
	if failure, failed := s.fileErrors[input]; failed {
		state.Status, state.Error = StatusFailed, failure.Error
		if filepath.Dir(failure.ErrorLogPath) == s.fileOutputDirs[input] {
			state.ErrorLog = filepath.Base(failure.ErrorLogPath)
		}
	}
	return writeChildState(s.fileOutputDirs[input], state)
}

func readRootJSON(root *os.Root, name string, target any) error {
	data, err := readRootMetadata(root, name)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func readRootMetadata(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("child metadata exceeds 16 MiB")
	}
	return data, nil
}

func childRecoveredState(root *os.Root, child childAnalysis, source string) localChildState {
	state := localChildState{Version: 1, Status: StatusFailed, Error: "Analysis interrupted before durable completion; retry creates a new child"}
	var saved localChildState
	stateErr := readRootJSON(root, "analysis-state.json", &saved)
	if stateErr == nil && saved.Version == 1 {
		state.ProcessingTime = saved.ProcessingTime
		if saved.Status == StatusFailed {
			state = saved
		}
	} else if stateErr == nil || !os.IsNotExist(stateErr) {
		state.Error = "Child state is corrupt or unavailable"
		return state
	}
	f, err := root.Open(source)
	if err != nil {
		state.Error = "Retained child input is missing or inaccessible"
		return state
	}
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	f.Close()
	if err != nil || hex.EncodeToString(hash.Sum(nil)) != child.InputSHA256 {
		state.Error = "Retained child input does not match its SHA256"
		return state
	}
	if saved.Status == StatusFailed {
		return state
	}
	if child.PacketSelection != nil {
		data, err := readRootMetadata(root, "packet-selection.json")
		hash := sha256.Sum256(data)
		if err != nil || hex.EncodeToString(hash[:]) != child.PacketManifestSHA256 {
			state.Error = "Subset selection manifest is missing or changed"
			return state
		}
	}
	var manifest evidence.CaptureManifest
	var ready rules.OfflineReadyMarker
	if (saved.Status == StatusCompleted || os.IsNotExist(stateErr)) && readRootJSON(root, "capture-manifest.json", &manifest) == nil && (manifest.Status == "done" || manifest.Status == "complete") && manifest.RunID != "" &&
		manifest.InputSHA256 == child.InputSHA256 && readRootJSON(root, rules.OfflineReadyFile, &ready) == nil && ready.Version == 1 && ready.RunID == manifest.RunID {
		state.Status, state.Error = StatusCompleted, ""
	}
	return state
}

func withinAnalysisRoot(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Inspect immediate owned run directories only; never recursively crawl user inputs.
func (s *Server) discoverLocalChildren() error {
	base, err := filepath.Abs(s.baseOutDir)
	if err != nil || s.baseOutDir == "" {
		return err
	}
	allowed := map[string]bool{base: true}
	for _, dir := range s.fileOutputDirs {
		if abs, err := filepath.Abs(dir); err == nil {
			allowed[abs] = true
		}
	}
	candidates := make(map[string]childAnalysis)
	metadataBytes := 0
	candidateCount := 0
	for _, scan := range []string{base, filepath.Dir(base)} {
		entries, err := os.ReadDir(scan)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "analysis-") {
				continue
			}
			candidateCount++
			if candidateCount > 4096 {
				return fmt.Errorf("child discovery exceeds 4096 candidates")
			}
			dir := filepath.Join(scan, entry.Name())
			root, err := os.OpenRoot(dir)
			if err != nil {
				continue
			}
			var child childAnalysis
			data, err := readRootMetadata(root, "analysis-parent.json")
			if err == nil {
				err = json.Unmarshal(data, &child)
			}
			root.Close()
			if err != nil || child.Version != 1 || child.AnalysisID != entry.Name() || len(child.InputSHA256) != 64 || child.CreatedAt.IsZero() {
				log.Printf("[WebUI] Ignoring invalid child metadata in %s", dir)
				continue
			}
			if child.Selector != "whole-capture" && child.Selector != "packet-subset" {
				continue
			}
			if child.Selector == "packet-subset" && (child.PacketSelection == nil || child.PacketSelection.validate(child.ParentRunID) != nil || len(child.PacketManifestSHA256) != 64) {
				continue
			}
			metadataBytes += len(data) + 512
			if metadataBytes > 64<<20 {
				return fmt.Errorf("child discovery exceeds 4096 candidates or 64 MiB accounted metadata")
			}
			candidates[dir] = child
		}
	}
	ids := make(map[string]int)
	for _, child := range candidates {
		ids[child.AnalysisID]++
	}
	for dir, child := range candidates {
		if ids[child.AnalysisID] > 1 {
			log.Printf("[WebUI] Ignoring duplicate child ID %s in %s", child.AnalysisID, dir)
			delete(candidates, dir)
		}
	}
	for progress := true; progress; {
		progress = false
		for dir, child := range candidates {
			parent, err := filepath.Abs(child.ParentOutputDir)
			boundRoot := child.AnalysisRoot == base
			if err != nil || (!boundRoot && !allowed[parent] && !withinAnalysisRoot(base, parent)) {
				continue
			}
			if !withinAnalysisRoot(base, dir) && filepath.Dir(dir) != filepath.Dir(base) {
				continue
			}
			if s.restoreLocalChild(dir, child) {
				allowed[dir] = true
				progress = true
			}
			delete(candidates, dir)
		}
	}
	return nil
}

func (s *Server) restoreLocalChild(dir string, child childAnalysis) bool {
	name := child.InputFilename
	if name == "" {
		name = filepath.Base(child.ParentInputFile)
	}
	if name != filepath.Base(name) || name == "." || name == ".." {
		return false
	}
	source := filepath.Join("source", name)
	if child.ParentInputFile == "" || filepath.Base(child.ParentInputFile) == "." {
		return false
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	defer root.Close()
	// A missing input remains a failed visible run; a symlink is not an owned copy.
	if info, err := root.Lstat(source); err == nil {
		if !info.Mode().IsRegular() {
			return false
		}
	} else if !os.IsNotExist(err) {
		return false
	}
	state := childRecoveredState(root, child, source)
	input := filepath.Join(dir, source)
	if existing, exists := s.fileIDToPath[child.AnalysisID]; exists && existing != input {
		log.Printf("[WebUI] Ignoring duplicate child ID %s", child.AnalysisID)
		return false
	}
	if s.childAnalyses == nil {
		s.childAnalyses = make(map[string]childAnalysis)
	}
	s.childAnalyses[input] = child
	s.fileIDToPath[child.AnalysisID] = input
	s.fileOutputDirs[input] = dir
	s.fileBPFFilters[input] = child.BPFFilter
	s.fileProcessingTime[input] = state.ProcessingTime
	if !slices.Contains(s.inputFiles, input) {
		s.inputFiles = append(s.inputFiles, input)
	}
	if state.Status == StatusCompleted {
		s.completedFiles[input] = true
	} else {
		failure := FileError{InputFile: input, Error: state.Error, Timestamp: time.Now().Unix()}
		if state.ErrorLog != "" && state.ErrorLog == filepath.Base(state.ErrorLog) {
			if info, err := root.Lstat(state.ErrorLog); err == nil && info.Mode().IsRegular() {
				failure.ErrorLogPath = filepath.Join(dir, state.ErrorLog)
			}
		}
		s.fileErrors[input] = failure
	}
	return true
}
