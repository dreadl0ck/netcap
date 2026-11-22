package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/internal/dpi"
)

type analysisSettingsPatch struct {
	DPI                    *bool   `json:"dpi,omitempty"`
	DPIModules             *string `json:"dpiModules,omitempty"`
	Payload                *bool   `json:"payload,omitempty"`
	RetainPackets          *bool   `json:"retainPackets,omitempty"`
	SegmentMB              *int64  `json:"segmentMB,omitempty"`
	RetentionMB            *int64  `json:"retentionMB,omitempty"`
	MaxTCPBytes            *int64  `json:"maxTCPBytes,omitempty"`
	MaxReassemblyBytes     *int64  `json:"maxReassemblyBytes,omitempty"`
	MaxTCPStateBytes       *int64  `json:"maxTCPStateBytes,omitempty"`
	MaxAggregateStateBytes *int64  `json:"maxAggregateStateBytes,omitempty"`
	IncrementalHTTP        *bool   `json:"incrementalHTTP,omitempty"`
	CaptureTimeIdleExpiry  *bool   `json:"captureTimeIdleExpiry,omitempty"`
	FlowExports            *bool   `json:"flowExports,omitempty"`
	FlowExportPorts        *string `json:"flowExportPorts,omitempty"`
}

func (s *Server) runtimeSnapshotLocked() RuntimeConfig {
	rc := RuntimeConfig{CaptureEvidence: true, FlowExports: true, PacketSegmentBytes: 32 << 20, PacketRetentionBytes: 512 << 20,
		MaxRetainedTCPBytes: defaults.MaxRetainedTCPBytes, MaxRetainedReassemblyBytes: defaults.MaxRetainedReassemblyBytes,
		MaxRetainedTCPStateBytes: defaults.MaxRetainedTCPStateBytes, MaxAggregateStateBytes: defaults.MaxAggregateStateBytes}
	if s.runtimeConfig != nil {
		rc = *s.runtimeConfig
	}
	return rc
}

func (s *Server) configuredDPI() bool { s.mu.RLock(); defer s.mu.RUnlock(); return s.dpiConfigured }

func (s *Server) handleAnalysisSettings(w http.ResponseWriter, r *http.Request) {
	p := PresentationFromRequest(r)
	presentationHeaders(w, p)
	if s.isServiceMode && !captureAdminAuthorized(r) {
		uiHTTPError(w, r, "analysis settings require service administrator identity", 403, "analysis_settings_unauthorized", "Analysis settings require administrator access")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		uiHTTPError(w, r, "method not allowed", 405, "method_not_allowed", "Method not allowed")
		return
	}
	var patch analysisSettingsPatch
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
		if err != nil {
			uiHTTPError(w, r, "settings request exceeds bounds", 400, "analysis_settings_too_large", "Invalid analysis settings")
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) == 0 {
			uiHTTPError(w, r, "nonempty settings patch required", 400, "analysis_settings_empty", "Invalid analysis settings")
			return
		}
		for _, value := range fields {
			if string(value) == "null" {
				uiHTTPError(w, r, "null settings are not applied; omit unchanged fields", 400, "analysis_settings_null", "Invalid analysis settings")
				return
			}
		}
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if err := d.Decode(&patch); err != nil {
			uiHTTPError(w, r, err.Error(), 400, "analysis_settings_invalid", "Invalid analysis settings")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rc := s.runtimeSnapshotLocked()
	enabled, payload := s.dpiConfigured, s.payloadCapture
	if r.Method == http.MethodPost {
		if patch.DPI != nil {
			if *patch.DPI && !dpi.HasDPISupport() {
				uiHTTPError(w, r, "DPI unavailable in this build", 422, "dpi_unavailable", "DPI unavailable in this build")
				return
			}
			enabled = *patch.DPI
		}
		if patch.DPIModules != nil {
			for _, module := range strings.Split(*patch.DPIModules, ",") {
				if module != "" && module != "go" && module != "ndpi" && module != "lpi" {
					uiHTTPError(w, r, "DPI modules must be go,ndpi,lpi CSV or empty", 400, "analysis_settings_dpi_modules", "Invalid analysis settings")
					return
				}
			}
			rc.DPIModules = *patch.DPIModules
		}
		if patch.Payload != nil {
			payload = *patch.Payload
			rc.Payload = payload
		}
		if patch.RetainPackets != nil {
			rc.RetainPackets = *patch.RetainPackets
		}
		for name, item := range map[string]struct {
			value  *int64
			target *int64
			max    int64
			shift  uint
		}{
			"segmentMB": {patch.SegmentMB, &rc.PacketSegmentBytes, 1024, 20}, "retentionMB": {patch.RetentionMB, &rc.PacketRetentionBytes, 16384, 20},
			"maxTCPBytes": {patch.MaxTCPBytes, &rc.MaxRetainedTCPBytes, 1 << 30, 0}, "maxReassemblyBytes": {patch.MaxReassemblyBytes, &rc.MaxRetainedReassemblyBytes, 4 << 30, 0},
			"maxTCPStateBytes": {patch.MaxTCPStateBytes, &rc.MaxRetainedTCPStateBytes, 1 << 30, 0}, "maxAggregateStateBytes": {patch.MaxAggregateStateBytes, &rc.MaxAggregateStateBytes, 1 << 30, 0},
		} {
			if item.value != nil {
				if *item.value < 1 || *item.value > item.max {
					uiHTTPError(w, r, fmt.Sprintf("%s must be 1..%d", name, item.max), 400, "analysis_settings_range", "Analysis setting is outside the allowed range", map[string]any{"field": name, "min": 1, "max": item.max})
					return
				}
				*item.target = *item.value << item.shift
			}
		}
		if rc.PacketSegmentBytes > rc.PacketRetentionBytes {
			uiHTTPError(w, r, "packet retention must hold at least one segment", 400, "analysis_settings_retention", "Invalid analysis settings")
			return
		}
		if patch.IncrementalHTTP != nil {
			rc.IncrementalHTTP = *patch.IncrementalHTTP
		}
		if patch.CaptureTimeIdleExpiry != nil {
			rc.CaptureTimeIdleExpiry = *patch.CaptureTimeIdleExpiry
		}
		if patch.FlowExports != nil {
			rc.FlowExports = *patch.FlowExports
		}
		if patch.FlowExportPorts != nil {
			if *patch.FlowExportPorts != "" {
				for _, port := range strings.Split(*patch.FlowExportPorts, ",") {
					n, err := strconv.ParseUint(strings.TrimSpace(port), 10, 16)
					if err != nil || n == 0 {
						uiHTTPError(w, r, "invalid flow export port CSV", 400, "analysis_settings_flow_ports", "Invalid analysis settings")
						return
					}
				}
			}
			rc.FlowExportPorts = *patch.FlowExportPorts
		}
		s.runtimeConfig = &rc
		s.dpiConfigured = enabled
		s.payloadCapture = payload
	}
	RespondJSON(w, 200, map[string]any{"dpi": enabled, "dpiSupported": dpi.HasDPISupport(), "dpiModules": rc.DPIModules, "payload": payload, "retainPackets": rc.RetainPackets, "segmentMB": rc.PacketSegmentBytes >> 20, "retentionMB": rc.PacketRetentionBytes >> 20, "maxTCPBytes": rc.MaxRetainedTCPBytes, "maxReassemblyBytes": rc.MaxRetainedReassemblyBytes, "maxTCPStateBytes": rc.MaxRetainedTCPStateBytes, "maxAggregateStateBytes": rc.MaxAggregateStateBytes, "incrementalHTTP": rc.IncrementalHTTP, "captureTimeIdleExpiry": rc.CaptureTimeIdleExpiry, "flowExports": rc.FlowExports, "flowExportPorts": rc.FlowExportPorts, "scope": "subsequent analyses; active and retained results are unchanged; component budgets exclude RSS", "scopeI18n": p.message("config.analysis.scope", "subsequent analyses; active and retained results are unchanged; component budgets exclude RSS", nil)})
}
