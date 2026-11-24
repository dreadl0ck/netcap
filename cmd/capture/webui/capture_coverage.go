package webui

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/internal/exitcode"
)

// partialCaptureCoverage returns the coverage reason a sealed capture
// manifest records for a partial run.
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

// acceptPartialCapture reports whether a failed capture is a coverage exit
// whose output is complete for what was read: exit 2 (partial input,
// reassembly or artifact budget) or exit 3 (some link types unsupported).
// Since v0.16.11 the CLI uses these codes; they are not analysis failures.
//
// Exit 2 is also how Go reports a crash, so acceptance needs this run's
// capture-input.json, rewritten as finalized after cleanup closed every
// writer, and at least one packet decoded past the link layer. This holds
// with capture evidence off, as in service mode. fallback supplies the
// coverage note when neither the manifest nor the input report names one.
func acceptPartialCapture(err error, dir string, started time.Time, fallback func() string) (string, bool) {
	code := exitcode.Code(err)
	if code != 2 && code != 3 {
		return "", false
	}
	f, info, openErr := artifactio.Open(dir, collector.CaptureInputFile)
	if openErr != nil {
		return "", false
	}
	var report collector.CaptureInputReport
	decodeErr := json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(&report)
	f.Close()
	if decodeErr != nil || !report.Finalized || info.ModTime().Before(started.Truncate(time.Second)) {
		return "", false
	}
	if report.ProcessedPackets-report.LinkErrors-report.Unsupported <= 0 {
		return "", false
	}
	switch report.Status {
	case "partial", "complete":
		if code == 3 {
			return "", false
		}
	case "unsupported":
	default:
		return "", false
	}
	if note, ok := partialCaptureCoverage(dir); ok {
		return note, true
	}
	if report.Status != "complete" {
		return (&collector.CaptureInputError{Report: report}).Error(), true
	}
	if fallback != nil {
		if note := fallback(); note != "" {
			return note, true
		}
	}
	return "capture completed with partial coverage", true
}
