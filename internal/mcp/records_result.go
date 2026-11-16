package mcp

import (
	"encoding/json"
	"sort"
)

func (s *Server) completeRecordJSON(ref SessionRef, kind string, record json.RawMessage) (json.RawMessage, error) {
	if len(record) <= 80<<10 {
		return record, nil
	}
	entry, uri, err := s.carve.PutTyped(ref.ID, "audit-record", kind, "application/json", record)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(record, &object)
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return json.Marshal(map[string]any{"_oversized": true, "artifact_id": entry.ID, "resource_uri": uri, "sha256": entry.SHA256, "size_bytes": entry.SizeBytes, "fields": keys, "next_step": "Use fields to project structured values or read_mcp_artifact to read the complete JSON in bounded byte pages."})
}
