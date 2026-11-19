package webui

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"
)

func (s *Server) discoverServiceChildren(results string) error {
	base, err := filepath.Abs(results)
	if err != nil {
		return err
	}
	names, err := scanChildRecoveryNames(base, maxChildRecoveryCandidates)
	if err != nil {
		return err
	}
	budget := childDiscoveryBudget(maxChildDiscoveryBytes)
	for _, candidate := range names {
		if err := budget.admitCandidate(); err != nil {
			return err
		}
		dir := filepath.Join(base, candidate)
		root, err := os.OpenRoot(dir)
		if err != nil {
			continue
		}
		data, readErr := budget.read(root, "analysis-parent.json")
		if errors.Is(readErr, errChildDiscoveryBudget) {
			root.Close()
			return readErr
		}
		sessionData, sessionErr := budget.read(root, "session.json")
		if errors.Is(sessionErr, errChildDiscoveryBudget) {
			root.Close()
			return sessionErr
		}
		var child childAnalysis
		var session SessionInfo
		if readErr != nil || sessionErr != nil || json.Unmarshal(data, &child) != nil || json.Unmarshal(sessionData, &session) != nil ||
			child.Version != 1 || child.AnalysisID != candidate || session.SessionID != child.AnalysisID || session.IsPreloaded || session.IP == "" ||
			child.ParentSessionID == "" || session.ParentSessionID != child.ParentSessionID || child.CreatedAt.IsZero() || !session.UploadTimestamp.Equal(child.CreatedAt) {
			root.Close()
			log.Printf("[WebUI] Ignoring invalid service child metadata in %s", dir)
			continue
		}
		parent, parentErr := filepath.Abs(child.ParentOutputDir)
		if child.Selector != "whole-capture" && child.Selector != "packet-subset" {
			root.Close()
			continue
		}
		if child.Selector == "packet-subset" && (child.PacketSelection == nil || child.PacketSelection.validate(child.ParentRunID) != nil || len(child.PacketManifestSHA256) != 64) {
			root.Close()
			continue
		}
		storedOutput, outputErr := filepath.Abs(session.OutputDir)
		name := child.InputFilename
		if name == "" {
			name = filepath.Base(child.ParentInputFile)
		}
		if name != filepath.Base(name) || name == "." || name == ".." || parentErr != nil || outputErr != nil || !withinAnalysisRoot(base, parent) || storedOutput != dir {
			root.Close()
			continue
		}
		source := filepath.Join("source", name)
		input := filepath.Join(dir, source)
		storedInput, err := filepath.Abs(session.InputFile)
		if err != nil || storedInput != input {
			root.Close()
			continue
		}
		if info, err := root.Lstat(source); err == nil {
			if !info.Mode().IsRegular() {
				root.Close()
				continue
			}
		} else if !os.IsNotExist(err) {
			root.Close()
			continue
		}
		if s.sessionManager.sessionExpiryMin > 0 && time.Since(session.UploadTimestamp) > time.Duration(s.sessionManager.sessionExpiryMin)*time.Minute {
			root.Close()
			continue
		}
		state := childRecoveredState(root, child, source)
		root.Close()
		if session.Status != StatusCompleted || state.Status != StatusCompleted {
			previousStatus, previousError := session.Status, session.ErrorMessage
			session.Status, session.ResultsReady, session.ErrorLogPath = StatusFailed, false, ""
			session.ErrorMessage = state.Error
			if previousStatus == StatusFailed && previousError != "" && (state.Status == StatusCompleted || state.Error == "Analysis interrupted before durable completion; retry creates a new child") {
				session.ErrorMessage = previousError
			}
			if session.ErrorMessage == "" {
				session.ErrorMessage = "Analysis interrupted before durable completion; retry creates a new child"
			}
		} else {
			session.ResultsReady = true
		}
		session.InputFile, session.OutputDir = input, dir
		session.ParentRunID, session.AnalysisSelector, session.PacketSelection = child.ParentRunID, child.Selector, child.PacketSelection
		if err := writeAnalysisJSON(dir, "session.json", session); err != nil {
			return err
		}
		s.sessionManager.AddSession(&session)
	}
	return nil
}
