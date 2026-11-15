package mcp

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dreadl0ck/netcap/internal/behavior"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

var behaviorCollections = []string{"observed", "approved", "labels", "corrections", "leases", "rates", "approvedRates", "activity", "suppressed", "decisions"}

func behaviorSnapshotTool() apiTool {
	return apiTool{
		name: "get_behavior", path: "/api/behavior", session: true,
		description:    "Read behavioral baseline version, mode, learning/coverage counters and collection counts with one bounded fact/inventory page. Default section=observed, limit=25. Entries retain original keyed values; pass section=summary for metadata only. Version is required for change_behavior.",
		options:        []mcplib.ToolOption{apiString("section", "Collection to page, or summary for metadata only.", false, append([]string{"summary"}, behaviorCollections...)...), apiInteger("limit", "Entries per page (default 25).", 1, 100, false), apiInteger("offset", "Entry offset in sorted-key order (decision history keeps its stored order).", 0, 100000, false)},
		localArguments: []string{"section", "limit", "offset"}, project: projectBehaviorSnapshot,
	}
}

func projectBehaviorSnapshot(raw json.RawMessage, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	var snapshot map[string]json.RawMessage
	if err := json.Unmarshal(raw, &snapshot); err != nil || snapshot == nil {
		return nil, fmt.Errorf("invalid behavioral snapshot")
	}
	if string(snapshot["schema"]) != fmt.Sprint(behavior.SchemaVersion) || len(snapshot["version"]) == 0 {
		return nil, fmt.Errorf("behavioral schema %d and baseline version required", behavior.SchemaVersion)
	}
	section := req.GetString("section", "observed")
	counts := map[string]int{}
	var selected json.RawMessage
	for _, name := range behaviorCollections {
		value := snapshot[name]
		if name == section {
			selected = value
		}
		delete(snapshot, name)
		if name == "decisions" {
			var rows []json.RawMessage
			if len(value) > 0 && json.Unmarshal(value, &rows) != nil {
				return nil, fmt.Errorf("invalid behavior decisions")
			}
			counts[name] = len(rows)
		} else {
			var rows map[string]json.RawMessage
			if len(value) > 0 && json.Unmarshal(value, &rows) != nil {
				return nil, fmt.Errorf("invalid behavior %s", name)
			}
			counts[name] = len(rows)
		}
	}
	type entry struct {
		ID    string          `json:"id"`
		Value json.RawMessage `json:"value"`
	}
	entries := []entry{}
	limit, offset := req.GetInt("limit", 25), req.GetInt("offset", 0)
	total := counts[section]
	if section == "decisions" {
		var rows []json.RawMessage
		_ = json.Unmarshal(selected, &rows)
		for i := offset; i < len(rows) && len(entries) < limit; i++ {
			entries = append(entries, entry{ID: fmt.Sprint(i), Value: rows[i]})
		}
	} else if section != "summary" {
		var rows map[string]json.RawMessage
		_ = json.Unmarshal(selected, &rows)
		keys := make([]string, 0, len(rows))
		for key := range rows {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i := offset; i < len(keys) && len(entries) < limit; i++ {
			entries = append(entries, entry{ID: keys[i], Value: rows[keys[i]]})
		}
	}
	out := map[string]any{}
	for key, value := range snapshot {
		out[key] = value
	}
	out["counts"], out["section"], out["entries"] = counts, section, entries
	out["total"], out["limit"], out["offset"], out["has_more"] = total, limit, offset, offset+len(entries) < total
	return jsonResult(out), nil
}
