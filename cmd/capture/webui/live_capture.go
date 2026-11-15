package webui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type liveCaptureRequest struct {
	Interface       string `json:"interface"`
	BPF             string `json:"bpf"`
	DurationSeconds int    `json:"durationSeconds"`
	RetentionMB     int64  `json:"retentionMB"`
}

type ownedLiveCapture struct {
	SessionID string             `json:"session_id"`
	Interface string             `json:"interface"`
	Output    string             `json:"-"`
	Completed bool               `json:"completed"`
	Error     string             `json:"error,omitempty"`
	Deadline  time.Time          `json:"deadline"`
	StartedAt time.Time          `json:"started_at"`
	Cancel    context.CancelFunc `json:"-"`
}

func (s *Server) handleOwnedLiveCapture(w http.ResponseWriter, r *http.Request) {
	if s.isServiceMode {
		http.Error(w, "host live capture is local-mode only; hosted tenant sessions cannot include host interface traffic", 403)
		return
	}
	if r.Method == http.MethodGet {
		var selectedInput string
		if r.URL.Query().Has("sessionId") || r.URL.Query().Has("inputFile") {
			selected, err := s.resolveCaptureSelection(r)
			if err != nil {
				writeSelectionError(w, err)
				return
			}
			selectedInput = selected.InputFile
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		state := s.ownedLive
		if selectedInput != "" {
			state = s.liveInputs[selectedInput]
		}
		if selectedInput != "" && state == nil {
			http.Error(w, "not the owned live capture", 404)
			return
		}
		processing := s.processingLocked()
		if state != nil {
			processing = !state.Completed
		}
		RespondJSON(w, 200, map[string]any{"capture": state, "is_live_mode": s.isLiveMode && state == s.ownedLive, "is_processing": processing})
		return
	}
	if r.Method == http.MethodDelete {
		s.deleteOwnedLive(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var request liveCaptureRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF || request.DurationSeconds < 1 || request.DurationSeconds > 300 || request.RetentionMB < 1 || request.RetentionMB > 512 || len(request.BPF) > 4096 {
		http.Error(w, "require interface, durationSeconds 1..300 and retentionMB 1..512", 400)
		return
	}
	if _, err := net.InterfaceByName(request.Interface); err != nil {
		http.Error(w, "unknown network interface", 400)
		return
	}
	if list := strings.TrimSpace(os.Getenv("NC_LIVE_INTERFACES")); list != "" {
		allowed := false
		for _, name := range strings.Split(list, ",") {
			if strings.TrimSpace(name) == request.Interface {
				allowed = true
			}
		}
		if !allowed {
			http.Error(w, "interface is outside NC_LIVE_INTERFACES", 403)
			return
		}
	}
	if request.BPF != "" {
		if err := validateBPFFilter(request.BPF); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}
	if err := r.Context().Err(); err != nil {
		http.Error(w, err.Error(), 408)
		return
	}
	s.enqueueMu.RLock()
	defer s.enqueueMu.RUnlock()
	s.mu.Lock()
	if len(s.liveInputs) >= 8 {
		s.mu.Unlock()
		http.Error(w, "owned live capture capacity 8 reached; delete completed captures", 429)
		return
	}
	if s.processingStopping || s.processingLocked() || s.isLiveMode {
		s.mu.Unlock()
		http.Error(w, "capture backend is busy or stopping", 409)
		return
	}
	s.processingWork++
	s.isLiveMode = true
	base := s.baseOutDir
	s.mu.Unlock()
	accepted := false
	defer func() {
		if !accepted {
			s.mu.Lock()
			s.processingWork--
			s.isLiveMode = false
			s.mu.Unlock()
		}
	}()
	if base == "" {
		http.Error(w, "capture storage is unavailable", 503)
		return
	}
	out, err := os.MkdirTemp(base, "live-")
	if err != nil {
		http.Error(w, "cannot create owned capture output", 500)
		return
	}
	defer func() {
		if !accepted {
			_ = os.RemoveAll(out)
		}
	}()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		http.Error(w, "cannot allocate capture identity", 500)
		return
	}
	id := hex.EncodeToString(random[:])
	input := filepath.Join(out, "live.pcapng")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.DurationSeconds)*time.Second)
	snapshot, err := s.snapshotJobSettings()
	if err != nil {
		cancel()
		http.Error(w, err.Error(), 422)
		return
	}
	defer func() {
		if !accepted {
			snapshot.cleanup()
		}
	}()
	snapshot.Runtime.CaptureEvidence = true
	snapshot.Runtime.RetainPackets = true
	snapshot.Runtime.PacketSegmentBytes = 1 << 20
	snapshot.Runtime.PacketRetentionBytes = request.RetentionMB << 20
	snapshot.Runtime.MaxRetainedTCPBytes = 16 << 20
	snapshot.Runtime.MaxRetainedReassemblyBytes = 64 << 20
	snapshot.Runtime.MaxRetainedTCPStateBytes = 16 << 20
	snapshot.Runtime.MaxAggregateStateBytes = 16 << 20
	if _, err := s.settingsForJob(&AnalysisJob{settings: snapshot, OutputDir: out}); err != nil {
		cancel()
		http.Error(w, err.Error(), 500)
		return
	}
	if err := r.Context().Err(); err != nil {
		cancel()
		http.Error(w, err.Error(), 408)
		return
	}
	args := append([]string{"capture", "-iface=" + request.Interface, "-out=" + out, "-http=", "-quiet", "-y", "-promisc=false"}, snapshot.helperArgs()...)
	args = append(args, "-bpf="+request.BPF, "-include="+s.loadDecoderConfig().IncludeDecoders, "-exclude="+s.loadDecoderConfig().ExcludeDecoders)
	runner := s.liveRunner
	if runner == nil {
		runner = s.startLiveHelper
	}
	wait, err := runner(ctx, args, out)
	if err != nil {
		cancel()
		http.Error(w, "cannot start capture helper: "+err.Error(), 503)
		return
	}
	state := &ownedLiveCapture{SessionID: id, Interface: request.Interface, Output: out, StartedAt: time.Now(), Deadline: time.Now().Add(time.Duration(request.DurationSeconds) * time.Second), Cancel: cancel}
	s.mu.Lock()
	s.inputFiles = append(s.inputFiles, input)
	s.fileIDToPath[id] = input
	s.fileOutputDirs[input] = out
	s.completedFiles[input] = false
	s.fileBPFFilters[input] = request.BPF
	s.ownedLive = state
	if s.liveInputs == nil {
		s.liveInputs = map[string]*ownedLiveCapture{}
	}
	s.liveInputs[input] = state
	s.stopCapture = cancel
	s.outDir = out
	s.activeInputFile = input
	s.wg.Add(2)
	s.mu.Unlock()
	accepted = true
	go func() {
		defer s.wg.Done()
		defer cancel()
		defer snapshot.cleanup()
		err := wait()
		message := ""
		if err != nil {
			message = liveCaptureFailure(err, out)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		state.Completed = true
		if err != nil {
			state.Error = message
		}
		if state.Error != "" {
			s.fileErrors[input] = FileError{InputFile: input, Error: state.Error, Timestamp: time.Now().Unix(), ErrorLogPath: filepath.Join(out, "live-capture.log")}
		}
		s.completedFiles[input] = state.Error == ""
		s.isLiveMode = false
		s.stopCapture = nil
		s.processingWork--
	}()
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var size int64
				count := 0
				err := filepath.WalkDir(out, func(path string, entry os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					count++
					if count > 10000 {
						return fmt.Errorf("capture output entry budget exceeded")
					}
					if !entry.IsDir() {
						info, err := entry.Info()
						if err != nil {
							return err
						}
						size += info.Size()
						if size > (request.RetentionMB+64)<<20 {
							return fmt.Errorf("capture output disk budget exceeded")
						}
					}
					return nil
				})
				if err != nil {
					s.mu.Lock()
					state.Error = err.Error()
					s.mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	RespondJSON(w, 202, map[string]any{"session_id": id, "interface": request.Interface, "duration_seconds": request.DurationSeconds, "retention_mb": request.RetentionMB})
}

func (s *Server) deleteOwnedLive(w http.ResponseWriter, r *http.Request) {
	if !r.URL.Query().Has("sessionId") && !r.URL.Query().Has("inputFile") {
		http.Error(w, "explicit live capture selector required", 400)
		return
	}
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.liveInputs[selected.InputFile]
	if state == nil || state.Output != selected.OutputDir {
		http.Error(w, "not an owned live capture", 404)
		return
	}
	if !state.Completed {
		http.Error(w, "stop and wait for live capture before deletion", 409)
		return
	}
	if err := os.RemoveAll(state.Output); err != nil {
		http.Error(w, "cannot remove owned capture output", 500)
		return
	}
	delete(s.liveInputs, selected.InputFile)
	delete(s.completedFiles, selected.InputFile)
	delete(s.fileErrors, selected.InputFile)
	delete(s.fileOutputDirs, selected.InputFile)
	delete(s.fileIDToPath, state.SessionID)
	kept := s.inputFiles[:0]
	for _, input := range s.inputFiles {
		if input != selected.InputFile {
			kept = append(kept, input)
		}
	}
	s.inputFiles = kept
	if s.activeInputFile == selected.InputFile {
		s.activeInputFile = ""
		s.outDir = s.baseOutDir
	}
	if s.ownedLive == state {
		s.ownedLive = nil
	}
	RespondJSON(w, 200, map[string]any{"session_id": state.SessionID, "deleted": true})
}
