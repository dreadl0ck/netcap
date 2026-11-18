package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

var streamVerificationSlots = make(chan struct{}, 2)

func (s *Server) handleStreamContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	selected, err := s.resolveCaptureSelection(r)
	if err != nil {
		writeSelectionError(w, err)
		return
	}
	q := r.URL.Query()
	id, direction := q.Get("id"), q.Get("direction")
	if !strings.HasPrefix(id, "stream-") || filepath.Base(id) != id || strings.ContainsAny(id, "/\\\x00") || (direction != "client" && direction != "server") {
		http.Error(w, "require stream id and client/server direction", 400)
		return
	}
	limit, offset := 65536, int64(0)
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
		if err != nil || limit < 1 || limit > 65536 {
			http.Error(w, "limit must be 1..65536", 400)
			return
		}
	}
	if q.Has("offset") {
		offset, err = strconv.ParseInt(q.Get("offset"), 10, 64)
		if err != nil || offset < 0 || offset > 256<<20 {
			http.Error(w, "invalid offset", 400)
			return
		}
	}
	spanOffset, spanLimit := 0, 64
	if q.Has("spanOffset") {
		spanOffset, err = strconv.Atoi(q.Get("spanOffset"))
		if err != nil || spanOffset < 0 || spanOffset > 1000000 {
			http.Error(w, "invalid spanOffset", 400)
			return
		}
	}
	if q.Has("spanLimit") {
		spanLimit, err = strconv.Atoi(q.Get("spanLimit"))
		if err != nil || spanLimit < 1 || spanLimit > 128 {
			http.Error(w, "spanLimit must be 1..128", 400)
			return
		}
	}
	expected := q.Get("manifestSHA256")
	if offset > 0 && expected == "" {
		http.Error(w, "stream manifest changed or required for subsequent page", 409)
		return
	}
	select {
	case streamVerificationSlots <- struct{}{}:
		defer func() { <-streamVerificationSlots }()
	default:
		http.Error(w, "stream verification is busy", http.StatusTooManyRequests)
		return
	}
	manifestPath := filepath.Join("stream-evidence", id, "manifest.json")
	raw, err := artifactio.Read(r.Context(), selected.OutputDir, manifestPath, 16<<20)
	if err != nil {
		http.Error(w, "stream manifest unavailable", 404)
		return
	}
	digest := sha256.Sum256(raw)
	manifestHash := hex.EncodeToString(digest[:])
	if expected != "" && expected != manifestHash {
		http.Error(w, "stream manifest changed or required for subsequent page", 409)
		return
	}
	var manifest streamutils.StreamEvidenceManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Version != 1 {
		http.Error(w, "invalid stream manifest", 422)
		return
	}
	file := manifest.Client
	if direction == "server" {
		file = manifest.Server
	}
	f, info, err := artifactio.Open(selected.OutputDir, filepath.Join("stream-evidence", id, direction+".bin"))
	if err != nil {
		http.Error(w, "stream bytes unavailable", 404)
		return
	}
	defer f.Close()
	if info.Size() > 256<<20 || info.Size() != file.Length {
		http.Error(w, "stream size does not match manifest", 409)
		return
	}
	hash := sha256.New()
	buffer := make([]byte, 65536)
	chunk := make([]byte, min(int64(limit), max(0, info.Size()-offset)))
	var scanned int64
	for {
		if err := r.Context().Err(); err != nil {
			http.Error(w, err.Error(), 408)
			return
		}
		n, err := f.Read(buffer)
		start := scanned
		scanned += int64(n)
		if scanned > info.Size() {
			http.Error(w, "stream changed during read", 409)
			return
		}
		hash.Write(buffer[:n])
		// Return bytes from the same read used for verification.
		lo, hi := max(offset, start), min(offset+int64(len(chunk)), scanned)
		if lo < hi {
			copy(chunk[lo-offset:hi-offset], buffer[lo-start:hi-start])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "stream read failed", 500)
			return
		}
	}
	if scanned != info.Size() || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		http.Error(w, "stream bytes do not match manifest", 409)
		return
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		http.Error(w, "stream changed during read", 409)
		return
	}
	spanCount := len(manifest.Spans)
	spanOffset = min(spanOffset, spanCount)
	spanEnd := min(spanOffset+spanLimit, spanCount)
	spans := append([]streamutils.StreamEvidenceSpan{}, manifest.Spans[spanOffset:spanEnd]...)
	manifest.Spans = nil
	RespondJSON(w, 200, map[string]any{"id": id, "direction": direction, "offset": offset, "totalBytes": strconv.FormatInt(info.Size(), 10), "data": chunk, "encoding": "base64", "manifestSHA256": manifestHash, "manifest": manifest, "spanCount": spanCount, "spansOmitted": len(spans) < spanCount, "spans": spans, "spanOffset": spanOffset, "hasMoreSpans": spanEnd < spanCount, "hasMore": offset+int64(len(chunk)) < info.Size()})
}
