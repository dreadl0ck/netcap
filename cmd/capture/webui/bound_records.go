package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/analyst"
	"github.com/gogo/protobuf/proto"
)

// Buffer only the finite selected page; publish it after the entire file and
// generation have passed integrity checks, not while a snapshot is still forming.
func handleBoundAuditStream(w http.ResponseWriter, r *http.Request, path, typ string) {
	started := time.Now()
	q := r.URL.Query()
	allowed := map[string]bool{"sessionId": true, "inputFile": true, "runId": true, "sourceSHA256": true, "manifestSHA256": true, "evidence": true, "offset": true, "limit": true, "communityId": true, "filter": true}
	for key, values := range q {
		if !allowed[key] || (key != "communityId" && len(values) != 1) {
			http.Error(w, "Invalid bound stream query", 400)
			return
		}
	}
	if q.Get("evidence") != "1" || q.Get("filter") != "" {
		http.Error(w, "Bound stream version 1 supports unfiltered or exact Community ID views; use the catalogue for indicator queries", 400)
		return
	}
	source := analyst.SourceSelection{SessionID: q.Get("sessionId"), InputFile: q.Get("inputFile"), Binding: analyst.Binding{RunID: q.Get("runId"), SourceSHA256: q.Get("sourceSHA256"), ManifestSHA256: q.Get("manifestSHA256")}}
	if source.SessionID == "" && source.InputFile == "" {
		http.Error(w, "Explicit occurrence source required", 400)
		return
	}
	offset, limit := 0, 500
	for key, dest := range map[string]*int{"offset": &offset, "limit": &limit} {
		if value := q.Get(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				http.Error(w, "Invalid bound page", 400)
				return
			}
			*dest = n
		}
	}
	if offset < 0 || offset > analyst.MaxRecords || limit < 1 || limit > 500 {
		http.Error(w, "Bound page exceeds limits", 400)
		return
	}
	ids := map[string]bool{}
	if len(q["communityId"]) > 256 {
		http.Error(w, "Too many Community IDs", 400)
		return
	}
	for _, id := range q["communityId"] {
		if len(id) == 0 || len(id) > 256 {
			http.Error(w, "Invalid Community ID", 400)
			return
		}
		ids[id] = true
	}
	ctx, done, ok := analystContext(w, r)
	if !ok {
		return
	}
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	// Report stale bindings as conflicts before opening a data stream.
	if err := analyst.Check(ctx, filepath.Dir(path), source.Binding); err != nil {
		if err == context.Canceled || err == context.DeadlineExceeded {
			analystFailure(w, err)
		} else {
			http.Error(w, "Exact audit-stream binding required or stale", 409)
		}
		return
	}
	rows := []json.RawMessage{}
	scanned, matched := 0, 0
	err := analyst.Walk(ctx, filepath.Dir(path), source.Binding, typ, func(ref analyst.Reference, msg proto.Message) error {
		scanned++
		if len(ids) > 0 && !auditRecordMatchesCommunityID(msg, ids) {
			return nil
		}
		matched++
		if matched <= offset || len(rows) >= limit {
			return nil
		}
		data, err := analyst.RecordJSON(msg)
		if err != nil {
			return err
		}
		var object map[string]json.RawMessage
		if len(data) > 2000 {
			object = map[string]json.RawMessage{}
			object["_truncated"], _ = json.Marshal(true)
			object["_originalSize"], _ = json.Marshal(len(data))
			object["_truncatedData"], _ = json.Marshal(string(data[:2000]) + "...")
		} else if err = json.Unmarshal(data, &object); err != nil {
			return err
		}
		object["_netcapOccurrence"], _ = json.Marshal(ref)
		object["_netcapSource"], _ = json.Marshal(source)
		data, err = json.Marshal(object)
		if err != nil {
			return err
		}
		rows = append(rows, data)
		return nil
	})
	if err != nil {
		analystFailure(w, err)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		if _, err = fmt.Fprintf(w, "event: record\ndata: %s\n\n", row); err != nil {
			return
		}
		flusher.Flush()
	}
	complete, _ := json.Marshal(map[string]any{"total": matched, "count": len(rows), "scanned": scanned, "executionTimeMs": time.Since(started).Milliseconds(), "binding": source.Binding, "coverage": "retained-content-bound"})
	_, _ = fmt.Fprintf(w, "event: complete\ndata: %s\n\n", complete)
	flusher.Flush()
}
