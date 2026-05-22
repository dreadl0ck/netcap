/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package webui

import (
	"net/http"
	"path/filepath"
	"strings"
)

// resolveOutDirFromRequest picks the per-request output directory using
// (in order) an explicit ?sessionId= or ?inputFile= query parameter, then
// the server's global currentSession / outDir. This is the bridge that
// lets MCP tool calls scope analytical queries without mutating the
// shared currentSession state — multiple concurrent MCP requests against
// different sessions can now make progress in parallel.
//
// Returns ("", false) when no session context is available; callers
// should respond with 503/serviceUnavailable in that case (matching
// existing behaviour).
func (s *Server) resolveOutDirFromRequest(r *http.Request) (string, bool) {
	q := r.URL.Query()

	// Service mode: ?sessionId=<hex> wins.
	if sid := q.Get("sessionId"); sid != "" {
		if s.isServiceMode && s.sessionManager != nil {
			if sess, ok := s.sessionManager.GetSession(sid); ok && sess.OutputDir != "" {
				return sess.OutputDir, true
			}
		}
		// Fall through to inputFile / global if the sessionId didn't
		// resolve — useful when the LLM passes a local-mode session_id
		// that happens to look like a hex string.
	}

	// Local mode: ?inputFile=/abs/path.pcap, derived from /api/files/input.
	if path := q.Get("inputFile"); path != "" {
		if dir := s.outDirForInputFile(path); dir != "" {
			return dir, true
		}
	}

	// Legacy fallback: the globally-selected session/outDir. This keeps
	// the React frontend working unchanged because it doesn't pass query
	// params; only the MCP shim does.
	s.mu.RLock()
	dir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if sess, ok := s.sessionManager.GetSession(s.currentSession); ok {
			dir = sess.OutputDir
		}
	}
	s.mu.RUnlock()
	if dir == "" {
		return "", false
	}
	return dir, true
}

// outDirForInputFile mirrors the local-mode dispatch used in
// handleSetDirectory: prefer fileOutputDirs[path], else single-file mode
// uses baseOutDir, else derive from baseOutDir + the file's basename
// (stripped of a known pcap extension).
func (s *Server) outDirForInputFile(path string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if dir, ok := s.fileOutputDirs[path]; ok && dir != "" {
		return dir
	}
	if len(s.inputFiles) == 1 {
		return s.baseOutDir
	}
	base := filepath.Base(path)
	for _, ext := range []string{".pcap", ".pcapng", ".cap", ".dmp"} {
		if before, ok := strings.CutSuffix(base, ext); ok {
			base = before
			break
		}
	}
	return filepath.Join(s.baseOutDir, base)
}

// resolveInputFileFromRequest picks the per-request input file (the
// raw PCAP/PCAPNG on disk, used by tcpdump-shelling endpoints like
// /api/hosts/download-pcap). Uses ?sessionId= / ?inputFile= first,
// then the global activeInputFile.
func (s *Server) resolveInputFileFromRequest(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if sid := q.Get("sessionId"); sid != "" && s.isServiceMode && s.sessionManager != nil {
		if sess, ok := s.sessionManager.GetSession(sid); ok && sess.InputFile != "" {
			return sess.InputFile, true
		}
	}
	if path := q.Get("inputFile"); path != "" {
		return path, true
	}
	s.mu.RLock()
	active := s.activeInputFile
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if sess, ok := s.sessionManager.GetSession(s.currentSession); ok {
			active = sess.InputFile
		}
	}
	s.mu.RUnlock()
	if active == "" {
		return "", false
	}
	return active, true
}
