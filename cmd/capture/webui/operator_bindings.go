package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/mcp/bindings"
)

func (s *Server) operatorNetworkAllowed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	allowed := os.Getenv("NETCAP_MCP_ALLOW_FETCH") == "1"
	if s.runtimeConfig != nil && s.runtimeConfig.OperatorNetwork != nil {
		allowed = *s.runtimeConfig.OperatorNetwork
	}
	return allowed && os.Getenv("NETCAP_MCP_DISABLE_NETWORK") != "1"
}

func (s *Server) initOperatorBindings() error {
	s.mu.RLock()
	path := os.Getenv("NETCAP_MCP_BINDINGS_FILE")
	if s.runtimeConfig != nil && s.runtimeConfig.OperatorBindingsFile != nil {
		path = *s.runtimeConfig.OperatorBindingsFile
	}
	s.mu.RUnlock()
	manager, err := bindings.Load(path, s.operatorNetworkAllowed())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.operatorBindings = manager
	s.mu.Unlock()
	return nil
}
func (s *Server) operatorManager(w http.ResponseWriter, r *http.Request) *bindings.Manager {
	if s.isServiceMode && !captureAdminAuthorized(r) {
		http.Error(w, "operator binding requires administrator identity", 403)
		return nil
	}
	s.mu.RLock()
	manager := s.operatorBindings
	s.mu.RUnlock()
	if manager == nil {
		http.Error(w, "operator bindings unavailable", 503)
		return nil
	}
	return manager
}
func bindingResult(w http.ResponseWriter, result any, err error) {
	if err == nil {
		RespondJSON(w, 200, map[string]any{"report": result})
		return
	}
	status, code := 422, "operator_operation_failed"
	var fault *bindings.Fault
	if errors.As(err, &fault) {
		status, code = fault.Status, fault.Code
	} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		status, code = 408, "operator_operation_canceled"
	}
	RespondJSON(w, status, map[string]any{"report": result, "code": code, "operation_error": code})
}
func decodeBindingRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid operator request", 400)
		return false
	}
	return true
}
func (s *Server) operatorCapture(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	q := r.URL.Query()
	if (!q.Has("inputFile") && !q.Has("sessionId")) || q.Get("runId") == "" {
		http.Error(w, "explicit capture selector and runId required", 400)
		return "", "", false
	}
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return "", "", false
	}
	return selected.OutputDir, selected.RunID, true
}
func (s *Server) handleOperatorBindings(w http.ResponseWriter, r *http.Request) {
	manager := s.operatorManager(w, r)
	if manager == nil {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	RespondJSON(w, 200, manager.Public())
}
func (s *Server) handleSensorBinding(w http.ResponseWriter, r *http.Request) {
	manager := s.operatorManager(w, r)
	if manager == nil {
		return
	}
	var request bindings.SensorRequest
	if !decodeBindingRequest(w, r, &request) {
		return
	}
	source, run := "", ""
	if request.Operation == "seal" {
		var ok bool
		source, run, ok = s.operatorCapture(w, r)
		if !ok {
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	result, err := manager.SensorForCapture(ctx, request, source, run)
	bindingResult(w, result, err)
}
func (s *Server) handleSensorArchive(w http.ResponseWriter, r *http.Request) {
	manager := s.operatorManager(w, r)
	if manager == nil {
		return
	}
	q := r.URL.Query()
	allowed := map[string]bool{"binding": true}
	if r.Method == http.MethodGet {
		allowed["stage"] = true
		allowed["bundle_id"] = true
	}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 {
			http.Error(w, "invalid archive binding query", 400)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		data, err := manager.Export(ctx, q.Get("binding"), q.Get("stage"), q.Get("bundle_id"))
		if err != nil {
			bindingResult(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
	case http.MethodPost:
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		if err != nil {
			http.Error(w, "sensor archive exceeds budget", 413)
			return
		}
		result, err := manager.ImportArchive(ctx, q.Get("binding"), data)
		bindingResult(w, result, err)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func (s *Server) handleAlertDeliveryBinding(w http.ResponseWriter, r *http.Request) {
	manager := s.operatorManager(w, r)
	if manager == nil {
		return
	}
	var request bindings.DeliveryRequest
	if !decodeBindingRequest(w, r, &request) {
		return
	}
	source, run := "", ""
	if request.Operation == "enqueue" {
		var ok bool
		source, run, ok = s.operatorCapture(w, r)
		if !ok {
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	result, err := manager.Delivery(ctx, request, source, run)
	bindingResult(w, result, err)
}
