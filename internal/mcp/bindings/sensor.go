package bindings

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/collector"
	"github.com/dreadl0ck/netcap/internal/evidence"
)

type SensorRequest struct {
	Operation        string `json:"operation"`
	Binding          string `json:"binding"`
	BundleID         string `json:"bundle_id,omitempty"`
	Stage            string `json:"stage,omitempty"`
	RetentionSeconds int    `json:"retention_seconds,omitempty"`
	Limit            int    `json:"limit,omitempty"`
	Offset           int    `json:"offset,omitempty"`
}

func sensorStore(b *sensorBinding, stage string) (string, error) {
	if stage != "sealed" && stage != "imports" && stage != "inbox" {
		return "", fault(400, "invalid_sensor_stage")
	}
	root := filepath.Join(b.config.Namespace, stage)
	if err := privateDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}
func sensorBundle(b *sensorBinding, stage, id string) (string, error) {
	if !component.MatchString(id) {
		return "", fault(400, "invalid_bundle_id")
	}
	root, err := sensorStore(b, stage)
	if err != nil {
		return "", err
	}
	for _, path := range []string{filepath.Join(root, b.config.SensorID), filepath.Join(root, b.config.SensorID, id)} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fault(422, "sensor_bundle_unavailable")
		}
	}
	return filepath.Join(root, b.config.SensorID, id), nil
}
func (m *Manager) scope(b *sensorBinding) collector.SensorImportScope {
	return collector.SensorImportScope{SensorKeys: map[string][]byte{b.config.SensorID: b.key}, Now: m.now(), MaxBytes: b.config.MaxBytes, MaxRetention: time.Duration(b.config.RetentionSeconds) * time.Second}
}

func sensorCapacity(b *sensorBinding, stage string) error {
	root, err := sensorStore(b, stage)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, b.config.SensorID)
	entries, err := boundedEntries(dir, b.config.MaxRuns+64)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fault(503, "sensor_namespace_unavailable")
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			count++
		}
	}
	if count >= b.config.MaxRuns {
		return fault(409, "sensor_run_capacity")
	}
	return nil
}

// Snapshot before native sealing so its fixed 1 GiB ceiling cannot exceed enrollment.
func (m *Manager) copySource(ctx context.Context, source, target string, budget int64) error {
	if err := m.rejectSecretSource(source); err != nil {
		return err
	}
	entries, files, total := 0, 0, int64(0)
	return filepath.WalkDir(source, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return fault(422, "sensor_source_unavailable")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 10000 {
			return fault(422, "sensor_source_entry_budget")
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || len(strings.Split(filepath.ToSlash(rel), "/")) > 16 {
			return fault(422, "sensor_source_layout")
		}
		if e.Type()&os.ModeSymlink != 0 {
			return fault(422, "sensor_source_symlink")
		}
		if e.IsDir() {
			return nil
		}
		if strings.HasSuffix(e.Name(), ".log") {
			return nil
		}
		files++
		if files > 4096 || len(rel) > 512 {
			return fault(422, "sensor_source_layout")
		}
		f, info, err := artifactio.Open(source, rel)
		if err != nil {
			return fault(422, "sensor_source_unavailable")
		}
		f.Close()
		for _, secret := range m.secretFiles {
			if os.SameFile(info, secret) {
				return fault(403, "credential_in_source")
			}
		}
		data, err := artifactio.Read(ctx, source, rel, budget-total+1)
		if err != nil || int64(len(data)) > budget-total {
			return fault(422, "sensor_source_byte_budget_or_change")
		}
		total += int64(len(data))
		out := filepath.Join(target, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			return fault(503, "sensor_snapshot_unavailable")
		}
		if os.WriteFile(out, data, 0600) != nil {
			return fault(503, "sensor_snapshot_unavailable")
		}
		return nil
	})
}

func sensorSummary(path, binding string) (map[string]any, error) {
	raw, err := artifactio.Read(context.Background(), path, "sensor-bundle.json", 8<<20)
	if err != nil {
		return nil, fault(422, "sensor_metadata_unavailable")
	}
	var manifest collector.SensorManifest
	if json.Unmarshal(raw, &manifest) != nil {
		return nil, fault(422, "invalid_sensor_metadata")
	}
	var total int64
	for _, file := range manifest.Files {
		total += file.Bytes
	}
	return map[string]any{"binding": binding, "bundle_id": manifest.RunID, "sensor_id": manifest.SensorID, "input_sha256": manifest.InputSHA256, "files": len(manifest.Files), "bytes": total, "expires_ns": fmt.Sprint(manifest.ExpiresNs), "qualification": "HMAC proves possession of the enrolled shared key, not endpoint/user authentication"}, nil
}

// Sensor preserves the direct-call API without asserting an external generation.
// Authenticated adapters must use SensorForCapture for capture-bound sealing.
func (m *Manager) Sensor(ctx context.Context, r SensorRequest, source string) (any, error) {
	return m.sensorOperation(ctx, r, source, "")
}

// SensorForCapture receives the validated generation separately from request JSON.
func (m *Manager) SensorForCapture(ctx context.Context, r SensorRequest, source, expectedRun string) (any, error) {
	if r.Operation == "seal" && !component.MatchString(expectedRun) {
		return nil, fault(400, "validated_capture_run_required")
	}
	return m.sensorOperation(ctx, r, source, expectedRun)
}

func (m *Manager) sensorOperation(ctx context.Context, r SensorRequest, source, expectedRun string) (any, error) {
	b, err := m.sensor(r.Binding)
	if err != nil {
		return nil, err
	}
	release, err := acquire(ctx, b.gate)
	if err != nil {
		return nil, err
	}
	defer release()
	if r.Operation != "seal" && r.RetentionSeconds != 0 {
		return nil, fault(400, "unused_sensor_parameter")
	}
	if r.Operation != "list" && (r.Limit != 0 || r.Offset != 0) {
		return nil, fault(400, "unused_sensor_parameter")
	}
	if (r.Operation == "seal" || r.Operation == "prune") && (r.BundleID != "" || r.Stage != "") {
		return nil, fault(400, "unused_sensor_parameter")
	}
	switch r.Operation {
	case "seal":
		retention := r.RetentionSeconds
		if retention == 0 {
			retention = b.config.RetentionSeconds
		}
		if retention < 1 || retention > b.config.RetentionSeconds {
			return nil, fault(400, "retention_outside_enrollment")
		}
		if source == "" {
			return nil, fault(400, "explicit_capture_required")
		}
		if err := sensorCapacity(b, "sealed"); err != nil {
			return nil, err
		}
		stage, err := os.MkdirTemp(b.config.Namespace, ".seal-source-")
		if err != nil {
			return nil, fault(503, "sensor_snapshot_unavailable")
		}
		defer os.RemoveAll(stage)
		if err := m.copySource(ctx, source, stage, b.config.MaxBytes); err != nil {
			return nil, err
		}
		if expectedRun != "" {
			raw, err := artifactio.Read(ctx, stage, "capture-manifest.json", 8<<20)
			var manifest evidence.CaptureManifest
			if err != nil || json.Unmarshal(raw, &manifest) != nil || manifest.Version != 1 || manifest.RunID != expectedRun {
				return nil, fault(409, "sensor_capture_generation_changed")
			}
		}
		store, _ := sensorStore(b, "sealed")
		now := m.now()
		path, err := collector.SealSensorOutput(ctx, stage, store, b.config.SensorID, now, now.Add(time.Duration(retention)*time.Second), b.key)
		if err != nil {
			return nil, fault(422, "sensor_seal_failed")
		}
		return sensorSummary(path, r.Binding)
	case "import":
		stage := r.Stage
		if stage == "" {
			stage = "inbox"
		}
		if stage != "inbox" && stage != "sealed" {
			return nil, fault(400, "invalid_import_stage")
		}
		bundle, err := sensorBundle(b, stage, r.BundleID)
		if err != nil {
			return nil, err
		}
		raw, err := artifactio.Read(ctx, bundle, "sensor-bundle.json", 8<<20)
		var manifest collector.SensorManifest
		if err != nil || json.Unmarshal(raw, &manifest) != nil || manifest.RunID != r.BundleID {
			return nil, fault(422, "sensor_bundle_identity_mismatch")
		}
		return m.importSensor(ctx, b, r.Binding, bundle)
	case "prune":
		ids := []string{}
		for _, stage := range []string{"sealed", "imports"} {
			store, err := sensorStore(b, stage)
			if err != nil {
				return nil, err
			}
			removed, err := collector.PruneSensorImports(ctx, store, m.scope(b))
			for _, path := range removed {
				ids = append(ids, stage+"/"+filepath.Base(path))
			}
			if err != nil {
				return map[string]any{"removed": ids}, fault(422, "sensor_prune_verification_failed")
			}
		}
		return map[string]any{"binding": r.Binding, "removed": ids}, nil
	case "list":
		stage := r.Stage
		if stage == "" {
			stage = "imports"
		}
		store, err := sensorStore(b, stage)
		if err != nil {
			return nil, err
		}
		limit := r.Limit
		if limit == 0 {
			limit = 25
		}
		if limit < 1 || limit > 100 || r.Offset < 0 {
			return nil, fault(400, "invalid_sensor_page")
		}
		entries, err := boundedEntries(filepath.Join(store, b.config.SensorID), b.config.MaxRuns+64)
		if os.IsNotExist(err) {
			entries = nil
		} else if err != nil {
			return nil, fault(503, "sensor_namespace_unavailable")
		}
		ids := []string{}
		for _, entry := range entries {
			if entry.IsDir() && component.MatchString(entry.Name()) {
				ids = append(ids, entry.Name())
			}
		}
		sort.Strings(ids)
		start := min(r.Offset, len(ids))
		end := min(start+limit, len(ids))
		return map[string]any{"binding": r.Binding, "stage": stage, "bundle_ids": ids[start:end], "total": len(ids), "has_more": end < len(ids)}, nil
	default:
		return nil, fault(400, "invalid_sensor_operation")
	}
}

func (m *Manager) importSensor(ctx context.Context, b *sensorBinding, name, source string) (any, error) {
	if err := sensorCapacity(b, "imports"); err != nil {
		return nil, err
	}
	store, err := sensorStore(b, "imports")
	if err != nil {
		return nil, err
	}
	path, err := collector.ImportSensorOutput(ctx, source, store, m.scope(b))
	if err != nil {
		return nil, fault(422, "sensor_import_verification_failed")
	}
	return sensorSummary(path, name)
}

// ImportArchive stages only bounded regular members, then delegates all trust checks.
func (m *Manager) ImportArchive(ctx context.Context, name string, data []byte) (any, error) {
	b, err := m.sensor(name)
	if err != nil {
		return nil, err
	}
	release, err := acquire(ctx, b.gate)
	if err != nil {
		return nil, err
	}
	defer release()
	if len(data) > 16<<20 {
		return nil, fault(413, "sensor_archive_budget")
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(archive.File) > 4097 {
		return nil, fault(422, "invalid_sensor_archive")
	}
	stage, err := os.MkdirTemp(b.config.Namespace, ".import-source-")
	if err != nil {
		return nil, fault(503, "sensor_snapshot_unavailable")
	}
	defer os.RemoveAll(stage)
	var total uint64
	for _, entry := range archive.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name
		if !filepath.IsLocal(name) || filepath.Clean(name) != name || strings.ContainsAny(name, "\\\x00") || entry.Mode()&os.ModeSymlink != 0 || entry.FileInfo().IsDir() || len(name) > 512 {
			return nil, fault(422, "invalid_sensor_archive_path")
		}
		if entry.UncompressedSize64 > uint64(b.config.MaxBytes)+(8<<20)-total {
			return nil, fault(422, "sensor_archive_expansion_budget")
		}
		total += entry.UncompressedSize64
		if err := os.MkdirAll(filepath.Join(stage, filepath.Dir(name)), 0700); err != nil {
			return nil, fault(503, "sensor_snapshot_unavailable")
		}
		in, err := entry.Open()
		if err != nil {
			return nil, fault(422, "invalid_sensor_archive")
		}
		out, err := os.OpenFile(filepath.Join(stage, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			in.Close()
			return nil, fault(422, "duplicate_sensor_archive_path")
		}
		n, copyErr := io.Copy(out, io.LimitReader(&contextReader{ctx, in}, int64(entry.UncompressedSize64)+1))
		closeErr := out.Close()
		in.Close()
		if copyErr != nil || closeErr != nil || uint64(n) != entry.UncompressedSize64 {
			return nil, fault(422, "invalid_sensor_archive_content")
		}
	}
	return m.importSensor(ctx, b, name, stage)
}

type contextReader struct {
	context.Context
	io.Reader
}

type archiveBudget struct {
	writer    io.Writer
	remaining int
}

func (w *archiveBudget) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, fault(413, "sensor_archive_budget")
	}
	n, err := w.writer.Write(data)
	w.remaining -= n
	return n, err
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func (m *Manager) Export(ctx context.Context, name, stage, id string) ([]byte, error) {
	b, err := m.sensor(name)
	if err != nil {
		return nil, err
	}
	release, err := acquire(ctx, b.gate)
	if err != nil {
		return nil, err
	}
	defer release()
	if stage != "sealed" && stage != "imports" {
		return nil, fault(400, "invalid_export_stage")
	}
	bundle, err := sensorBundle(b, stage, id)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	writer := zip.NewWriter(&archiveBudget{&output, 16 << 20})
	var total int64
	count := 0
	err = filepath.WalkDir(bundle, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fault(422, "sensor_bundle_unavailable")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		count++
		if count > 4097 {
			return fault(422, "sensor_file_budget")
		}
		rel, err := filepath.Rel(bundle, path)
		if err != nil {
			return fault(422, "sensor_bundle_layout")
		}
		data, err := artifactio.Read(ctx, bundle, rel, b.config.MaxBytes+(8<<20)-total)
		if err != nil {
			return fault(422, "sensor_bundle_unavailable")
		}
		total += int64(len(data))
		member, err := writer.Create(rel)
		if err != nil {
			return err
		}
		if _, err := member.Write(data); err != nil {
			return err
		}
		if output.Len() > 16<<20 {
			return fault(413, "sensor_archive_budget")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if writer.Close() != nil || output.Len() > 16<<20 {
		return nil, fault(413, "sensor_archive_budget")
	}
	return output.Bytes(), nil
}
