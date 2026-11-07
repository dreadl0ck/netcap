package webui

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/evidence"
)

type childPacketSelection struct {
	Version        int    `json:"version"`
	SourceSHA256   string `json:"sourceSHA256"`
	BPF            string `json:"bpf"`
	StartNs        *int64 `json:"startNs,omitempty,string"`
	EndNs          *int64 `json:"endNs,omitempty,string"`
	MaxPackets     int    `json:"maxPackets"`
	MaxOutputBytes int64  `json:"maxOutputBytes,omitempty,string"`
}

func (selection *childPacketSelection) validate(run string) error {
	decoded, err := hex.DecodeString(selection.SourceSHA256)
	selection.BPF = strings.TrimSpace(selection.BPF)
	if selection.Version != 1 || run == "" || err != nil || len(decoded) != 32 ||
		len(selection.BPF) > 8192 || (selection.BPF == "" && selection.StartNs == nil) ||
		(selection.StartNs == nil) != (selection.EndNs == nil) ||
		(selection.StartNs != nil && *selection.EndNs < *selection.StartNs) {
		return selectionError(400, "Subset requires version 1, parent runId/sourceSHA256 and a valid BPF/time selection")
	}
	selection.SourceSHA256 = strings.ToLower(selection.SourceSHA256)
	if selection.MaxPackets == 0 {
		selection.MaxPackets = 1_000_000
	}
	if selection.MaxOutputBytes == 0 {
		selection.MaxOutputBytes = 256 << 20
	}
	if selection.MaxPackets < 1 || selection.MaxPackets > 1_000_000 || selection.MaxOutputBytes < 1 || selection.MaxOutputBytes > 1<<30 {
		return selectionError(400, "Subset limits require 1–1000000 packets and 1–1073741824 output bytes")
	}
	return nil
}

type boundedChildWriter struct {
	output    io.Writer
	remaining int64
}

func (w *boundedChildWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, fmt.Errorf("subset output byte limit exceeded")
	}
	n, err := w.output.Write(data)
	w.remaining -= int64(n)
	return n, err
}

func prepareSubsetInput(ctx context.Context, input, dir string, selection *childPacketSelection) (string, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	path := filepath.Join(dir, "source", "selected.pcapng")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", 0, err
	}
	writer := &boundedChildWriter{output: f, remaining: selection.MaxOutputBytes}
	manifest, exportErr := evidence.ExportPackets(ctx, input, writer, evidence.Selection{
		BPF: selection.BPF, StartNs: selection.StartNs, EndNs: selection.EndNs, MaxPackets: selection.MaxPackets})
	closeErr := f.Close()
	if exportErr != nil {
		if errors.Is(exportErr, context.Canceled) || errors.Is(exportErr, context.DeadlineExceeded) {
			return "", 0, selectionError(408, "Subset preparation canceled or timed out")
		}
		if strings.Contains(exportErr.Error(), "limit exceeded") {
			return "", 0, selectionError(413, exportErr.Error())
		}
		if strings.HasPrefix(exportErr.Error(), "compile packet selection:") {
			return "", 0, selectionError(400, exportErr.Error())
		}
		return "", 0, exportErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	if manifest.SourceSHA256 != selection.SourceSHA256 {
		return "", 0, selectionError(409, "Subset source no longer matches parent SHA256")
	}
	if manifest.Selected == 0 {
		return "", 0, selectionError(422, "Subset matched no packets")
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "packet-selection.json"), data, 0600)
	}
	if err != nil {
		return "", 0, err
	}
	return manifest.OutputSHA256, selection.MaxOutputBytes - writer.remaining, nil
}
