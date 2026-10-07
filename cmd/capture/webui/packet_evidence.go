package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

func serveConnectionEvidence(w http.ResponseWriter, r *http.Request, input string, selection connectionPacketSelection) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	archive, err := os.CreateTemp("", "netcap-evidence-*.zip")
	if err != nil {
		http.Error(w, "Failed to create evidence archive", http.StatusInternalServerError)
		return
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	manifest, err := writeConnectionEvidence(ctx, input, archive, selection)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, evidence.ErrNoMatchingPackets) {
			status = http.StatusNotFound
		}
		if isPCAPFilterTimeout(err) {
			status = http.StatusRequestTimeout
		}
		http.Error(w, fmt.Sprintf("Packet evidence export failed: %v", err), status)
		return
	}
	if manifest.Selected == 0 {
		http.Error(w, "No packets matched the requested tuple/time selection", http.StatusNotFound)
		return
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "Failed to read evidence archive", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="connection-evidence.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Netcap-Source-SHA256", manifest.SourceSHA256)
	http.ServeContent(w, r, "connection-evidence.zip", time.Time{}, archive)
}

func writeConnectionEvidence(ctx context.Context, input string, output io.Writer, selection connectionPacketSelection) (evidence.PacketManifest, error) {
	return evidence.WriteArchive(ctx, input, output, evidence.Selection{
		BPF: selection.bpf, StartNs: selection.start, EndNs: selection.end, MaxPackets: 1_000_000,
	})
}
