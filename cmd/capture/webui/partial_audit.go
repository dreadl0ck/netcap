package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

type sealedAuditQuery struct {
	Stage                              evidence.AuditStage
	RunID, Generation, Directory, File string
}
type sealedAuditQueryKey struct{}

func preparePartialAudit(r *http.Request, selection captureSelection) (*sealedAuditQuery, error) {
	q := r.URL.Query()
	values, present := q["allowPartial"]
	if !present {
		return nil, nil
	}
	if len(values) != 1 || (values[0] != "true" && values[0] != "false") {
		return nil, selectionError(400, "allowPartial must be one boolean")
	}
	if values[0] == "false" {
		return nil, nil
	}
	if r.Method != http.MethodGet {
		return nil, selectionError(400, "Partial admission requires a GET audit stream")
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/audit/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/audit/") || len(parts) != 2 || parts[1] != "stream" || q.Has("evidence") {
		return nil, selectionError(400, "Partial admission supports generic audit streams only")
	}
	if selection.OutputDir == "" || (!q.Has("sessionId") && !q.Has("inputFile")) {
		return nil, selectionError(400, "Partial admission requires an explicit capture")
	}
	if values, present := q["stageGeneration"]; present && (len(values) != 1 || values[0] == "") {
		return nil, selectionError(400, "Invalid stageGeneration")
	}
	offset := 0
	if q.Has("offset") {
		var err error
		offset, err = strconv.Atoi(q.Get("offset"))
		if err != nil || offset < 0 {
			return nil, selectionError(400, "Invalid partial offset")
		}
	}
	if offset > 0 && (q.Get("runId") == "" || q.Get("stageGeneration") == "") {
		return nil, selectionError(409, "Partial continuation requires runId and stageGeneration")
	}
	runID := selection.RunID
	if runID == "" {
		var manifest evidence.CaptureManifest
		if err := readEvidenceJSON(filepath.Join(selection.OutputDir, "capture-manifest.json"), &manifest); err != nil {
			return nil, selectionError(422, "Sealed capture generation is unavailable")
		}
		runID = manifest.RunID
	}
	stage, snapshot, err := evidence.ReadAuditStageContext(r.Context(), selection.OutputDir, runID, parts[0], q.Get("stageGeneration"))
	if err != nil {
		return nil, selectionError(422, fmt.Sprintf("Sealed audit stage unavailable: %v", err))
	}
	fileName := ""
	if stage.Records > 0 {
		for _, file := range stage.Files {
			if strings.HasSuffix(file.Name, ".ncap") || strings.HasSuffix(file.Name, ".ncap.gz") {
				if fileName != "" {
					return nil, selectionError(422, "Sealed stage has ambiguous protobuf outputs")
				}
				fileName = file.Name
			}
		}
		if fileName == "" {
			return nil, selectionError(422, "Sealed stage has no queryable protobuf output")
		}
	}
	return &sealedAuditQuery{Stage: stage, RunID: snapshot.RunID, Generation: snapshot.Generation, Directory: selection.OutputDir, File: fileName}, nil
}

func partialAuditContext(r *http.Request) *sealedAuditQuery {
	value, _ := r.Context().Value(sealedAuditQueryKey{}).(*sealedAuditQuery)
	return value
}

func withPartialAudit(r *http.Request, query *sealedAuditQuery) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sealedAuditQueryKey{}, query))
}

func auditCompletion(w http.ResponseWriter, r *http.Request, total, scanned, count, offset int, elapsed int64, countOnly bool) {
	hasMore := !countOnly && offset+count < total
	sealed := partialAuditContext(r)
	if sealed == nil {
		_, _ = fmt.Fprintf(w, "event: complete\ndata: {\"total\": %d, \"scanned\": %d, \"count\": %d, \"executionTimeMs\": %d, \"nextOffset\": %d, \"hasMore\": %t}\n\n", total, scanned, count, elapsed, offset+count, hasMore)
		return
	}
	result := map[string]any{"total": total, "scanned": scanned, "count": count, "executionTimeMs": elapsed, "nextOffset": offset + count, "hasMore": hasMore}
	result["coverage"] = sealed.Stage.Coverage
	result["coverageReason"] = sealed.Stage.Reason
	result["stage"] = sealed.Stage.Stage
	result["runId"] = sealed.RunID
	result["stageGeneration"] = sealed.Generation
	result["partialAdmission"] = true
	data, _ := json.Marshal(result)
	_, _ = fmt.Fprintf(w, "event: complete\ndata: %s\n\n", data)
}
