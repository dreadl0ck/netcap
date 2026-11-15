package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/analyst"
	"github.com/dreadl0ck/netcap/internal/mcp/bindings"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

type sensorCall struct {
	Operation        string `json:"operation" jsonschema:"enum=list,enum=seal,enum=import,enum=export,enum=prune"`
	Binding          string `json:"binding"`
	SessionID        string `json:"session_id,omitempty"`
	RunID            string `json:"run_id,omitempty"`
	BundleID         string `json:"bundle_id,omitempty"`
	Stage            string `json:"stage,omitempty" jsonschema:"enum=sealed,enum=imports,enum=inbox"`
	ArtifactID       string `json:"artifact_id,omitempty"`
	RetentionSeconds int    `json:"retention_seconds,omitempty"`
	Limit            int    `json:"limit,omitempty"`
	Offset           int    `json:"offset,omitempty"`
}
type deliveryCall struct {
	Operation  string `json:"operation" jsonschema:"enum=enqueue,enum=status,enum=deliver"`
	Binding    string `json:"binding"`
	SessionID  string `json:"session_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	DeliveryID string `json:"delivery_id,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

func operatorReply(raw json.RawMessage, err error) (any, error) {
	status := 0
	if err != nil {
		var backend *BackendError
		if !errors.As(err, &backend) {
			return nil, fmt.Errorf("operator backend unavailable")
		}
		raw = backend.Body
		status = backend.StatusCode
	}
	var reply struct {
		Report json.RawMessage `json:"report"`
		Code   string          `json:"code"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return nil, fmt.Errorf("operator request rejected (HTTP %d)", status)
	}
	if status != 0 {
		return reply.Report, fmt.Errorf("operator request rejected (HTTP %d, %s)", status, truncate(reply.Code, 128))
	}
	if len(reply.Report) == 0 {
		return nil, fmt.Errorf("invalid operator response")
	}
	return reply.Report, nil
}

func (s *Server) registerBindingTools() error {
	if err := s.registerAPITool(apiTool{name: "get_operator_bindings", path: "/api/mcp/operator/bindings", description: "Discover optional startup-enrolled sensor/webhook binding names, limits and configured/network state. No keys, credential references, namespace paths or webhook URLs are returned. Empty enrollment is explicitly unconfigured."}); err != nil {
		return err
	}
	if err := s.registerAPITool(apiTool{name: "sensor_bundle", post: true, destructive: true, description: "Use a named operator-enrolled sensor authority. seal requires explicit session_id/run_id and optionally shorter retention; import accepts a bundle_id in the enrolled inbox/sealed namespace OR an owned sensor-bundle artifact_id; export returns a bounded signed ZIP artifact; list/prune act only within enrollment. No per-call keys, identities, paths or namespaces are accepted. HMAC proves shared-key possession, not endpoint authentication.", options: []mcplib.ToolOption{wireInputSchema[sensorCall]()}, run: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var r sensorCall
		if err := analyst.DecodeStrict(raw, &r); err != nil {
			return nil, err
		}
		if r.Operation != "seal" && (r.SessionID != "" || r.RunID != "" || r.RetentionSeconds != 0) {
			return nil, fmt.Errorf("capture/retention parameters are only valid for seal")
		}
		if r.Operation != "list" && (r.Limit != 0 || r.Offset != 0) {
			return nil, fmt.Errorf("pagination parameters are only valid for list")
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		client := s.newClient()
		if r.Operation == "export" {
			if r.ArtifactID != "" {
				return nil, fmt.Errorf("artifact_id is only valid for import")
			}
			stage := r.Stage
			if stage == "" {
				stage = "sealed"
			}
			query := url.Values{"binding": {r.Binding}, "stage": {stage}, "bundle_id": {r.BundleID}}
			data, mime, err := client.GetRawContext(ctx, "/api/mcp/operator/sensor-archive", query)
			if err != nil {
				return nil, fmt.Errorf("sensor export rejected")
			}
			if mime != "application/zip" {
				return nil, fmt.Errorf("invalid sensor archive response")
			}
			entry, uri, err := s.carve.PutTyped("", "sensor-bundle", "operator-binding:"+r.Binding, mime, data)
			if err != nil {
				return nil, err
			}
			return map[string]any{"binding": r.Binding, "bundle_id": r.BundleID, "artifact_id": entry.ID, "resource_uri": uri, "sha256": entry.SHA256, "size_bytes": entry.SizeBytes, "content_type": mime}, nil
		}
		if r.ArtifactID != "" {
			if r.Operation != "import" || r.BundleID != "" || r.Stage != "" {
				return nil, fmt.Errorf("artifact import cannot include a bundle path/stage")
			}
			entry := s.carve.Get(r.ArtifactID)
			if entry == nil || entry.Kind != "sensor-bundle" || entry.MIMEType != "application/zip" || entry.SessionID != "" {
				return nil, fmt.Errorf("owned sensor bundle artifact required")
			}
			result, err := client.postArchiveContext(ctx, "/api/mcp/operator/sensor-archive?"+url.Values{"binding": {r.Binding}}.Encode(), entry.Bytes)
			return operatorReply(result, err)
		}
		request := bindings.SensorRequest{Operation: r.Operation, Binding: r.Binding, BundleID: r.BundleID, Stage: r.Stage, RetentionSeconds: r.RetentionSeconds, Limit: r.Limit, Offset: r.Offset}
		path := "/api/mcp/operator/sensor"
		if r.Operation == "seal" {
			if strings.TrimSpace(r.SessionID) == "" || strings.TrimSpace(r.RunID) == "" {
				return nil, fmt.Errorf("explicit capture and run required")
			}
			query := newSessionRef(r.SessionID).sessionQueryParams()
			query.Set("runId", r.RunID)
			path += "?" + query.Encode()
		}
		result, err := client.PostJSONContext(ctx, path, request)
		return operatorReply(result, err)
	}}); err != nil {
		return err
	}
	return s.registerAPITool(apiTool{name: "alert_delivery", post: true, openWorld: true, description: "Durable alert delivery through a named startup-enrolled webhook binding. enqueue requires session_id/run_id and derives stable capture scope; status/deliver use the returned delivery_id so retries survive source expiry and restart. deliver obeys existing network policy. Limits remain within enrollment; pending/rejected notices are explicit errors, and receivers must deduplicate Idempotency-Key. No destination, token, arbitrary payload or outbox path is accepted.", options: []mcplib.ToolOption{wireInputSchema[deliveryCall]()}, run: func(ctx context.Context, raw json.RawMessage) (any, error) {
		var r deliveryCall
		if err := analyst.DecodeStrict(raw, &r); err != nil {
			return nil, err
		}
		if r.Operation == "deliver" && !s.networkAllowed {
			return nil, fmt.Errorf("network policy disables delivery")
		}
		path := "/api/mcp/operator/delivery"
		if r.Operation == "enqueue" {
			if strings.TrimSpace(r.SessionID) == "" || strings.TrimSpace(r.RunID) == "" || r.DeliveryID != "" {
				return nil, fmt.Errorf("enqueue requires explicit capture/run, not a delivery_id")
			}
			query := newSessionRef(r.SessionID).sessionQueryParams()
			query.Set("runId", r.RunID)
			path += "?" + query.Encode()
		} else if r.SessionID != "" || r.RunID != "" || r.DeliveryID == "" {
			return nil, fmt.Errorf("status/deliver require only an existing delivery_id scope")
		}
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		result, err := s.newClient().PostJSONContext(ctx, path, bindings.DeliveryRequest{Operation: r.Operation, Binding: r.Binding, DeliveryID: r.DeliveryID, Limit: r.Limit})
		return operatorReply(result, err)
	}})
}
