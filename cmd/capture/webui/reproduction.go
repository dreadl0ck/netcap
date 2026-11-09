package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/internal/analyst"
	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

type reproductionAttachment struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	SHA256 string `json:"sha256,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

// Metadata-only by construction: no raw logs, source paths, payloads or free-text errors.
func (s *Server) handleReproductionBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	selected, selectionErr := s.resolveCaptureSelection(r)
	if selectionErr != nil {
		writeSelectionError(w, selectionErr)
		return
	}
	if selected.OutputDir == "" {
		if s.writeFailedReproduction(w, r, selected) {
			return
		}
		http.Error(w, "No output directory selected", http.StatusServiceUnavailable)
		return
	}
	data, err := artifactio.Read(r.Context(), selected.OutputDir, "capture-manifest.json", 4<<20)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			if s.writeFailedReproduction(w, r, selected) {
				return
			}
			status = http.StatusNotFound
		}
		http.Error(w, "Capture manifest unavailable; reproduction metadata cannot be exported", status)
		return
	}
	var capture evidence.CaptureManifest
	if json.Unmarshal(data, &capture) != nil || capture.Version != 1 || !validHexIdentity(capture.RunID, 16) {
		http.Error(w, "Invalid capture manifest", 422)
		return
	}
	if selected.RunID != "" && selected.RunID != capture.RunID {
		http.Error(w, "Capture generation changed", 409)
		return
	}
	status := "unknown"
	for _, allowed := range []string{"running", "done", "complete", "partial", "error", "stopped"} {
		if capture.Status == allowed {
			status = allowed
		}
	}
	attachments := []reproductionAttachment{{Name: "capture-manifest.json", State: "projected", SHA256: digestBytes(data), Bytes: len(data)}}
	for _, name := range []string{"audit-output-ready.json", "analysis-parent.json", "packet-selection.json", "artifact-analysis.json"} {
		data, err := artifactio.Read(r.Context(), selected.OutputDir, name, 4<<20)
		a := reproductionAttachment{Name: name, State: "digest-only"}
		if errors.Is(err, os.ErrNotExist) {
			a.State = "missing"
		} else if err != nil {
			a.State = "read-failed"
		} else if !json.Valid(data) {
			a.State = "invalid-json"
		} else {
			a.SHA256, a.Bytes = digestBytes(data), len(data)
		}
		attachments = append(attachments, a)
	}
	attachments = append(attachments, reproductionAttachment{Name: "logs-and-payloads", State: "omitted-sensitive"})
	config := capture.Config
	bundle := map[string]any{
		"schema": "netcap-reproduction-metadata/v1", "state": "metadata-only",
		"exporter":        map[string]string{"version": netcap.Version, "commit": netcap.Commit},
		"producerVersion": "unavailable", "runId": capture.RunID, "captureStatus": status,
		"sourceSHA256": safeSHA256(capture.InputSHA256), "configSHA256": safeSHA256(capture.ConfigSHA256),
		"effectiveSettings": map[string]any{"snapLen": config.SnapLen, "workers": config.Workers, "reassembly": config.Reassembly,
			"retainPackets": config.RetainPackets, "segmentBytes": strconv.FormatInt(config.SegmentBytes, 10),
			"retentionBytes": strconv.FormatInt(config.RetentionBytes, 10), "maxRetainedTCPBytes": strconv.FormatInt(config.MaxRetainedTCPBytes, 10),
			"bpfSHA256": digestBytes([]byte(config.BPF)), "includeDecodersSHA256": digestBytes([]byte(config.IncludeDecoders)), "excludeDecodersSHA256": digestBytes([]byte(config.ExcludeDecoders))},
		"attachments": attachments,
		"limitations": []string{"Metadata-only bundle, not a self-contained replay", "Exporter version is not proof of the capture producer version", "Source hash is recorded provenance, not a fresh verification of the source file", "Free-text settings, source paths, logs, errors and payloads are omitted to avoid exporting credentials; attach separately only after analyst review", "Missing/read-failed attachments are not successful empty exports"},
	}
	if capture.Producer != nil {
		bundle["producer"] = reproductionProducer(capture.Producer)
		bundle["producerVersion"] = reproductionProducer(capture.Producer)["version"]
	}
	if r.URL.Query().Get("reviewedLog") == "true" {
		binding, e := analyst.BindDiagnostic(r.Context(), selected.OutputDir)
		if e != nil {
			analystFailure(w, e)
			return
		}
		review, e := analyst.ReviewedLog(r.Context(), selected.OutputDir, binding)
		if e != nil {
			analystFailure(w, e)
			return
		}
		bundle["reviewedLog"] = map[string]any{"version": review.Version, "name": "reviewed-diagnostic-log", "binding": review.Binding, "fileSHA256": review.FileSHA256, "start": review.Start, "end": review.End, "lines": review.Lines, "projectionSHA256": review.ProjectionSHA256, "state": review.State}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="netcap-reproduction-metadata.json"`)
	RespondJSON(w, http.StatusOK, bundle)
}

func reproductionProducer(producer *evidence.ProducerIdentity) map[string]any {
	value := func(raw, pattern string) string {
		if len(raw) <= 128 && regexp.MustCompile(pattern).MatchString(raw) {
			return raw
		}
		return "unavailable"
	}
	return map[string]any{"version": value(producer.Version, `^v[0-9]+\.[0-9]+\.[0-9]+$`), "commit": value(producer.Commit, `^([a-f0-9]{40}|development)$`), "goVersion": value(producer.GoVersion, `^go[0-9]+\.[0-9]+(\.[0-9]+)?$`), "platform": value(producer.Platform, `^(darwin|linux|windows|freebsd)/(amd64|arm64|386|arm|riscv64)$`), "executableRevision": value(producer.ExecutableRevision, `^[a-f0-9]{40}$`), "executableModified": producer.ExecutableModified, "coreModuleReplaced": producer.CoreModuleReplaced,
		"executableModuleSHA256": digestBytes([]byte(producer.ExecutableModule)), "coreModuleVersionSHA256": digestBytes([]byte(producer.CoreModuleVersion))}
}

func digestBytes(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }
func validHexIdentity(value string, size int) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == size
}
func safeSHA256(value string) string {
	if validHexIdentity(value, 32) {
		return value
	}
	return "unavailable"
}
