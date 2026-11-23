package webui

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

// partialCaptureCoverage returns the coverage reason of a capture that
// finished with sealed but partial output, such as a pcap with a few frames
// too short for their link header. Since v0.16.11 the capture exits 2 for
// these; the output is complete for what was readable and must stay usable.
func partialCaptureCoverage(dir string) (string, bool) {
	data, err := artifactio.Read(context.Background(), dir, "capture-manifest.json", 16<<20)
	if err != nil {
		return "", false
	}
	var manifest evidence.CaptureManifest
	if json.Unmarshal(data, &manifest) != nil || manifest.Status != "partial" || manifest.RunID == "" ||
		manifest.CoverageError == "" || manifest.AuditStagesGeneration == "" {
		return "", false
	}
	return manifest.CoverageError, true
}

// acceptPartialCapture reports whether a capture error is a coverage exit (2
// partial, 3 some link types unsupported) of a run whose manifest records
// sealed partial output.
func acceptPartialCapture(err error, dir string) (string, bool) {
	code := 0
	var exitErr *exec.ExitError
	var coded interface{ ExitCode() int }
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case errors.As(err, &coded):
		code = coded.ExitCode()
	}
	switch code {
	case 2:
	case 3:
		// Unsupported link types: accept a mixed-link capture where only some
		// packets are unsupported, never one where nothing was decodable.
		if !someLinksSupported(dir) {
			return "", false
		}
	default:
		return "", false
	}
	return partialCaptureCoverage(dir)
}

func someLinksSupported(dir string) bool {
	data, err := artifactio.Read(context.Background(), dir, "capture-input.json", 4<<20)
	if err != nil {
		return false
	}
	var report struct {
		Processed   int64 `json:"processedPackets"`
		Unsupported int64 `json:"unsupportedPackets"`
	}
	return json.Unmarshal(data, &report) == nil && report.Processed > report.Unsupported
}
