package bindings

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/internal/delivery"
	"github.com/dreadl0ck/netcap/internal/evidence"
	"github.com/dreadl0ck/netcap/types"
)

type DeliveryRequest struct {
	Operation  string `json:"operation"`
	Binding    string `json:"binding"`
	DeliveryID string `json:"delivery_id,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}
type deliveryScope struct {
	Version      int    `json:"version"`
	RunID        string `json:"run_id"`
	SourceSHA256 string `json:"source_sha256"`
}

func (m *Manager) Delivery(ctx context.Context, r DeliveryRequest, source, run string) (any, error) {
	b, err := m.webhook(r.Binding)
	if err != nil {
		return nil, err
	}
	if r.Operation == "deliver" && !m.network {
		return nil, fault(403, "network_policy_disabled")
	}
	if r.Operation != "enqueue" && r.Operation != "status" && r.Operation != "deliver" {
		return nil, fault(400, "invalid_delivery_operation")
	}
	if r.Operation == "status" && r.Limit != 0 {
		return nil, fault(400, "unused_delivery_parameter")
	}
	limit := r.Limit
	if limit == 0 {
		limit = b.config.MaxNotices
	}
	if limit < 1 || limit > b.config.MaxNotices {
		return nil, fault(400, "delivery_limit_outside_enrollment")
	}
	release, err := acquire(ctx, b.gate)
	if err != nil {
		return nil, err
	}
	defer release()
	var scope deliveryScope
	var id string
	var alerts []*types.Alert
	if r.Operation == "enqueue" {
		if source == "" || run == "" || r.DeliveryID != "" {
			return nil, fault(400, "bound_capture_required")
		}
		if err := m.rejectSecretSource(source); err != nil {
			return nil, err
		}
		raw, err := artifactio.Read(ctx, source, "capture-manifest.json", 8<<20)
		if err != nil {
			return nil, fault(422, "capture_manifest_unavailable")
		}
		var capture evidence.CaptureManifest
		if json.Unmarshal(raw, &capture) != nil || capture.Version != 1 || capture.RunID != run || capture.Status == "running" || !digestID.MatchString(capture.InputSHA256) {
			return nil, fault(409, "capture_identity_unavailable_or_stale")
		}
		scope = deliveryScope{1, capture.RunID, capture.InputSHA256}
		identity, _ := json.Marshal(scope)
		digest := sha256.Sum256(identity)
		id = hex.EncodeToString(digest[:])
		alerts, err = readAlerts(ctx, source, limit)
		if err != nil {
			return nil, err
		}
		current, err := artifactio.Read(ctx, source, "capture-manifest.json", 8<<20)
		if err != nil || !bytes.Equal(raw, current) {
			return nil, fault(409, "capture_identity_unavailable_or_stale")
		}
	} else {
		id = r.DeliveryID
		if !digestID.MatchString(id) {
			return nil, fault(400, "invalid_delivery_id")
		}
		raw, err := artifactio.Read(ctx, b.config.OutboxRoot, filepath.Join(id, "scope.json"), 4096)
		if err != nil || json.Unmarshal(raw, &scope) != nil || scope.Version != 1 {
			return nil, fault(404, "unknown_delivery_scope")
		}
		identity, _ := json.Marshal(scope)
		digest := sha256.Sum256(identity)
		if hex.EncodeToString(digest[:]) != id {
			return nil, fault(409, "delivery_scope_changed")
		}
	}
	directory := filepath.Join(b.config.OutboxRoot, id)
	if r.Operation == "enqueue" {
		if _, err := os.Lstat(directory); os.IsNotExist(err) {
			entries, err := boundedEntries(b.config.OutboxRoot, b.config.MaxScopes+64)
			if err != nil {
				return nil, fault(503, "outbox_root_unavailable")
			}
			count := 0
			for _, entry := range entries {
				if entry.IsDir() && digestID.MatchString(entry.Name()) {
					count++
				}
			}
			if count >= b.config.MaxScopes {
				return nil, fault(409, "delivery_scope_capacity")
			}
		}
		if err := privateDirectory(directory); err != nil {
			return nil, err
		}
		data, _ := json.Marshal(scope)
		path := filepath.Join(directory, "scope.json")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, err = f.Write(data)
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				return nil, fault(503, "outbox_scope_persistence_failed")
			}
		} else if !os.IsExist(err) {
			return nil, fault(503, "outbox_scope_unavailable")
		} else {
			stored, err := artifactio.Read(ctx, directory, "scope.json", 4096)
			if err != nil || !bytes.Equal(stored, data) {
				return nil, fault(409, "delivery_scope_changed")
			}
		}
	}
	if err := privateDirectory(directory); err != nil {
		return nil, err
	}
	for _, name := range []string{"alert-outbox.sqlite", "alert-outbox.sqlite-wal", "alert-outbox.sqlite-shm"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
			return nil, fault(409, "outbox_path_changed")
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, fault(503, "outbox_unavailable")
		}
	}
	// The native database also pins its destination digest across process restarts.
	box, err := delivery.Open(directory, b.config.Endpoint)
	if err != nil {
		return nil, fault(409, "outbox_unavailable_or_destination_changed")
	}
	defer box.Close()
	var operationErr error
	if r.Operation == "enqueue" {
		for _, alert := range alerts {
			if err := ctx.Err(); err != nil {
				operationErr = err
				break
			}
			if _, err := box.Enqueue(scope.RunID+":"+scope.SourceSHA256, alert); err != nil {
				operationErr = fault(422, "notice_rejected_or_outbox_full")
				break
			}
		}
	} else if r.Operation == "deliver" {
		if err := box.Deliver(ctx, limit, b.token); err != nil {
			operationErr = fault(422, "delivery_attempt_failed")
		}
	}
	status, err := box.Status()
	if err != nil {
		return nil, fault(503, "outbox_status_unavailable")
	}
	result := map[string]any{"binding": r.Binding, "delivery_id": id, "status": status, "qualification": "durable at-least-once delivery; receivers must deduplicate Idempotency-Key; retries/rejections remain visible"}
	if operationErr != nil {
		return result, operationErr
	}
	if r.Operation == "deliver" {
		if err := status.RequireDrained(); err != nil {
			return result, fault(422, "delivery_incomplete")
		}
	}
	return result, nil
}

type alertBudgetReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
}

func (r *alertBudgetReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.remaining <= 0 {
		return 0, fmt.Errorf("alert decoded budget exceeded")
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func readAlerts(ctx context.Context, source string, limit int) ([]*types.Alert, error) {
	f, info, err := artifactio.Open(source, "Alert.ncap.gz")
	if err != nil || info.Size() > 64<<20 {
		if f != nil {
			f.Close()
		}
		return nil, fault(422, "bounded_alert_source_unavailable")
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fault(422, "invalid_alert_source")
	}
	defer gz.Close()
	reader := delimited.NewReaderWithLimit(&alertBudgetReader{ctx, gz, 64 << 20}, 1<<20)
	var header types.Header
	if reader.NextProto(&header) != nil || header.Type != types.Type_NC_Alert {
		return nil, fault(422, "invalid_alert_header")
	}
	alerts := []*types.Alert{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var alert types.Alert
		err := reader.NextProto(&alert)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fault(422, "invalid_or_oversized_alert_source")
		}
		if len(alerts) >= limit {
			return nil, fault(422, "alert_input_exceeds_limit")
		}
		alerts = append(alerts, &alert)
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return nil, fault(409, "alert_source_changed")
	}
	return alerts, nil
}
