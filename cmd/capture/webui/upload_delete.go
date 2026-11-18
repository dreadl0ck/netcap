package webui

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func (s *Server) deleteLocalUpload(w http.ResponseWriter, r *http.Request) {
	id, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/api/try/session/"))
	if err != nil || id == "" {
		http.Error(w, "Explicit owned session required", 400)
		return
	}
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	s.currentJobMutex.RLock()
	defer s.currentJobMutex.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	input := s.fileIDToPath[id]
	if input == "" {
		input = id
	}
	owned, ok := s.localUploads[input]
	if !ok {
		http.Error(w, "Not an owned uploaded analysis", 403)
		return
	}
	if s.currentProcessing != nil && s.currentProcessing.InputFile == input {
		http.Error(w, "Analysis is still running", 409)
		return
	}
	_, failed := s.fileErrors[input]
	if !s.completedFiles[input] && !failed {
		http.Error(w, "Wait for queued/running analysis before deletion", 409)
		return
	}
	rootPath := filepath.Dir(filepath.Dir(input))
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		http.Error(w, "Owned storage unavailable", 409)
		return
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || owned.RootInfo == nil || !os.SameFile(info, owned.RootInfo) {
		http.Error(w, "Owned storage identity changed", 409)
		return
	}
	inputName := filepath.Join("uploads", owned.AnalysisID+strings.ToLower(filepath.Ext(owned.Filename)))
	output := filepath.Join(rootPath, owned.AnalysisID)
	if input != filepath.Join(rootPath, inputName) || s.fileOutputDirs[input] != output {
		http.Error(w, "Owned storage mapping changed", 409)
		return
	}
	for name, expected := range map[string]os.FileInfo{inputName: owned.InputInfo, owned.AnalysisID: owned.OutputInfo} {
		current, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || expected == nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(current, expected) {
			http.Error(w, "Owned artifact identity changed", 409)
			return
		}
	}
	if err := root.RemoveAll(owned.AnalysisID); err != nil {
		http.Error(w, "Cannot remove owned results", 500)
		return
	}
	if err := root.Remove(inputName); err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "Cannot remove owned upload", 500)
		return
	}
	delete(s.localUploads, input)
	delete(s.fileOutputDirs, input)
	delete(s.completedFiles, input)
	delete(s.fileErrors, input)
	delete(s.fileBPFFilters, input)
	delete(s.fileProcessingTime, input)
	delete(s.failedReproductions, input)
	for key, path := range s.fileIDToPath {
		if path == input {
			delete(s.fileIDToPath, key)
		}
	}
	s.inputFiles = slices.DeleteFunc(s.inputFiles, func(path string) bool { return path == input })
	if s.activeInputFile == input {
		s.activeInputFile = ""
		s.outDir = s.baseOutDir
	}
	clearOwnedAnalysisCaches(output)
	RespondJSON(w, 200, map[string]any{"success": true, "session_id": owned.AnalysisID, "input_file": input, "removed_paths": []string{input, output}})
}

func clearOwnedAnalysisCaches(out string) {
	timelineCache.Lock()
	if entry := timelineCache.entries[out]; entry != nil && entry.cancel != nil {
		close(entry.cancel)
	}
	delete(timelineCache.entries, out)
	timelineCache.Unlock()
	connectionCache.Lock()
	if entry := connectionCache.entries[out]; entry != nil {
		if entry.snapshot != nil {
			connectionCache.bytes -= entry.snapshot.bytes
		}
		delete(connectionCache.entries, out)
	}
	connectionCache.Unlock()
	certificateCache.Lock()
	if entry := certificateCache.entries[out]; entry != nil {
		if entry.snapshot != nil {
			certificateCache.bytes -= entry.snapshot.bytes
		}
		delete(certificateCache.entries, out)
	}
	certificateCache.Unlock()
	fingerprintCache.Lock()
	if entry := fingerprintCache.entries[out]; entry != nil {
		if entry.snapshot != nil {
			fingerprintCache.bytes -= entry.snapshot.bytes
		}
		delete(fingerprintCache.entries, out)
	}
	fingerprintCache.Unlock()
	vulnerabilityCache.Lock()
	if entry := vulnerabilityCache.entries[out]; entry != nil {
		if entry.snapshot != nil {
			vulnerabilityCache.bytes -= entry.snapshot.bytes
		}
		delete(vulnerabilityCache.entries, out)
	}
	vulnerabilityCache.Unlock()
	communityIndexCache.Lock()
	for path, entry := range communityIndexCache.files {
		if strings.HasPrefix(path, out+string(filepath.Separator)) {
			if entry.index != nil {
				communityIndexCache.bytes -= entry.index.bytes
			}
			delete(communityIndexCache.files, path)
		}
	}
	communityIndexCache.Unlock()
}
