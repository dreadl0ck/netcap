package mcp

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strconv"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

var pagedCollectionKeys = map[string]string{
	"list_hosts": "hosts", "list_devices": "devices", "list_services": "services",
	"list_domains": "domains", "list_http_records": "http", "list_certificates": "certificates",
	"list_software": "software", "list_secrets": "secrets", "list_alerts": "alerts",
	"list_extracted_files": "files", "list_rules": "rules",
	"list_alerts_grouped": "groups",
}

func pageInteger(req mcplib.CallToolRequest, key string, fallback, minimum, maximum int) (int, error) {
	value, ok := req.GetArguments()[key]
	if !ok {
		return fallback, nil
	}
	switch value.(type) {
	case float64, float32, int, int32, int64, json.Number:
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	number, err := strconv.ParseFloat(fmt.Sprint(value), 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < float64(minimum) || number > float64(maximum) {
		return 0, fmt.Errorf("%s must be an integer from %d to %d", key, minimum, maximum)
	}
	return int(number), nil
}

func collectionQuery(req mcplib.CallToolRequest, q url.Values) error {
	limit, err := pageInteger(req, "limit", 100, 1, 500)
	if err != nil {
		return err
	}
	offset, err := pageInteger(req, "offset", 0, 0, 1000000000)
	if err != nil {
		return err
	}
	q.Del("limit")
	q.Del("offset")
	q.Del("search")
	q.Set("mcpPage", "true")
	q.Set("pageLimit", strconv.Itoa(limit))
	q.Set("pageOffset", strconv.Itoa(offset))
	q.Set("pageSearch", req.GetString("search", ""))
	q.Set("pageFields", req.GetString("fields", ""))
	q.Set("pageGeneration", req.GetString("generation", ""))
	return nil
}

func (s *Server) collectionResult(ref SessionRef, key string, raw json.RawMessage) *mcplib.CallToolResult {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errResult(err)
	}
	if _, exists := envelope[key]; !exists {
		return rawJSONResult(raw)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(envelope[key], &rows); err != nil {
		return errResult(err)
	}
	for i, row := range rows {
		var err error
		rows[i], err = s.completeRecordJSON(ref, key, row)
		if err != nil {
			return errResult(err)
		}
	}
	envelope[key], _ = json.Marshal(rows)
	result, err := json.Marshal(envelope)
	if err != nil {
		return errResult(err)
	}
	return rawJSONResult(result)
}
