package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

func snapshotBoundedArtifact(ctx context.Context, directory, name, destination string, maxBytes int64) (string, error) {
	in, before, err := artifactio.Open(directory, name)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if before.Size() > maxBytes {
		return "", fmt.Errorf("source artifact exceeds %d bytes", maxBytes)
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, digest), io.LimitReader(&childInputReader{ctx: ctx, input: in}, maxBytes+1))
	closeErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	after, err := in.Stat()
	if err != nil || n > maxBytes || n != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", fmt.Errorf("source artifact changed or exceeded bounds")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func (s *Server) handlePacketExport(w http.ResponseWriter, r *http.Request) {
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
	expected := q.Get("sourceSHA256")
	if q.Get("runId") == "" || len(expected) != 64 {
		http.Error(w, "explicit runId and sourceSHA256 required", 400)
		return
	}
	selection := evidence.Selection{BPF: q.Get("bpf"), MaxPackets: 1000000}
	if selection.BPF == "" {
		selection.BPF = "len >= 0"
	}
	if q.Has("maxPackets") {
		selection.MaxPackets, err = strconv.Atoi(q.Get("maxPackets"))
		if err != nil || selection.MaxPackets < 1 || selection.MaxPackets > 1000000 {
			http.Error(w, "maxPackets must be 1..1000000", 400)
			return
		}
	}
	if q.Has("startNs") || q.Has("endNs") {
		start, e1 := strconv.ParseInt(q.Get("startNs"), 10, 64)
		end, e2 := strconv.ParseInt(q.Get("endNs"), 10, 64)
		if e1 != nil || e2 != nil || end < start {
			http.Error(w, "paired ordered startNs/endNs required", 400)
			return
		}
		selection.StartNs = &start
		selection.EndNs = &end
	}
	limit, err := packetDownloadLimit(r)
	if err != nil {
		writePacketDownloadLimitError(w, err)
		return
	}
	const maxArchiveBytes = 16 << 20
	if limit == 0 || limit > maxArchiveBytes {
		limit = maxArchiveBytes
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	release := s.admitSourceAnalysis(w, r)
	if release == nil {
		return
	}
	defer release()
	directory, name := filepath.Dir(selected.InputFile), filepath.Base(selected.InputFile)
	raw, err := artifactio.Read(ctx, selected.OutputDir, "capture-manifest.json", 16<<20)
	if err != nil {
		http.Error(w, "capture manifest unavailable", 422)
		return
	}
	var manifest evidence.CaptureManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Version != 1 || manifest.RunID != q.Get("runId") {
		http.Error(w, "capture manifest is stale", 409)
		return
	}
	if segment := q.Get("segment"); segment != "" {
		found := false
		for _, candidate := range manifest.Segments {
			if candidate.Name == segment && candidate.State == "retained" && candidate.SHA256 == expected {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "segment is unknown, active, expired or hash-mismatched", 409)
			return
		}
		directory, name = selected.OutputDir, segment
	} else if manifest.InputSHA256 != expected {
		http.Error(w, "original source hash does not match capture manifest; live captures require a retained segment", 409)
		return
	}
	dir, err := os.MkdirTemp("", "netcap-bound-packets-")
	if err != nil {
		http.Error(w, "cannot allocate packet snapshot", 500)
		return
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "source.pcapng")
	hash, err := snapshotBoundedArtifact(ctx, directory, name, input, 256<<20)
	if err != nil || hash != expected {
		http.Error(w, "packet source unavailable, changed or outside bounds", 409)
		return
	}
	archive, err := os.CreateTemp(dir, "evidence-*.zip")
	if err != nil {
		http.Error(w, "cannot allocate packet archive", 500)
		return
	}
	defer archive.Close()
	_, err = evidence.WriteArchive(ctx, input, &packetArchiveWriter{output: archive, remaining: limit}, selection)
	if err != nil {
		if writePacketDownloadLimitError(w, err) {
			return
		}
		http.Error(w, "packet evidence export failed: "+err.Error(), 422)
		return
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "cannot read packet archive", 500)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Netcap-Source-SHA256", hash)
	http.ServeContent(w, r, "packet-evidence.zip", time.Time{}, archive)
}
