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

func (s *Server) collectionResult(ref SessionRef, key string, raw json.RawMessage, query url.Values) *mcplib.CallToolResult {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return errResult(err)
	}
	paged := envelope["generation"] != nil || envelope["next_offset"] != nil || envelope["has_more"] != nil || envelope["returned"] != nil
	if _, exists := envelope[key]; !exists && !paged {
		return rawJSONResult(raw)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(envelope[key], &rows); err != nil {
		return errResult(err)
	}
	if paged {
		if err := validateCollectionPage(envelope, key, rows, query); err != nil {
			return errResult(err)
		}
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

func validateCollectionPage(envelope map[string]json.RawMessage, key string, rows []json.RawMessage, query url.Values) error {
	var offset, next, limit, returned, total int
	for _, field := range []struct {
		name string
		out  *int
	}{{"offset", &offset}, {"next_offset", &next}, {"limit", &limit}, {"returned", &returned}, {"totalCount", &total}} {
		*field.out = -1 // JSON null leaves an integer unchanged.
		if err := json.Unmarshal(envelope[field.name], field.out); err != nil || *field.out < 0 {
			return fmt.Errorf("invalid collection page %s", field.name)
		}
	}
	if key == "groups" {
		groupCount := -1
		if err := json.Unmarshal(envelope["groupCount"], &groupCount); err != nil || groupCount < 0 || groupCount > total {
			return fmt.Errorf("invalid collection page groupCount")
		}
		total = groupCount
	}
	var generation string
	var more *bool
	if json.Unmarshal(envelope["generation"], &generation) != nil || generation == "" || json.Unmarshal(envelope["has_more"], &more) != nil || more == nil {
		return fmt.Errorf("invalid collection page continuation metadata")
	}
	if rows == nil || offset > 1000000000 || limit < 1 || limit > 500 || returned != len(rows) || returned > limit || next != offset+returned ||
		(returned > 0 && next > total) || *more != (next < total) || (*more && returned == 0) {
		return fmt.Errorf("inconsistent collection page counts or continuation")
	}
	if query != nil && (query.Get("pageOffset") != strconv.Itoa(offset) || query.Get("pageLimit") != strconv.Itoa(limit)) {
		return fmt.Errorf("collection response does not match requested offset or limit")
	}
	if want := query.Get("pageGeneration"); want != "" && want != generation {
		return fmt.Errorf("collection response generation changed; restart pagination")
	}
	return nil
}
