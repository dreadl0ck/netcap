package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap/internal/flowexport"
)

func parseExportQuery(values url.Values) (flowexport.Query, error) {
	var q flowexport.Query
	for _, key := range []string{"startNs", "endNs", "exporter", "format", "domain", "timeBasis", "host", "groupBy", "limit"} {
		if len(values[key]) > 1 {
			return q, fmt.Errorf("duplicate export query parameter %s", key)
		}
	}
	start, err := strconv.ParseInt(values.Get("startNs"), 10, 64)
	if err != nil {
		return q, fmt.Errorf("invalid startNs")
	}
	end, err := strconv.ParseInt(values.Get("endNs"), 10, 64)
	if err != nil {
		return q, fmt.Errorf("invalid endNs")
	}
	domain, err := strconv.ParseUint(values.Get("domain"), 10, 32)
	if err != nil {
		return q, fmt.Errorf("invalid domain")
	}
	id := uint32(domain)
	q = flowexport.Query{StartNs: start, EndNs: end, Exporter: values.Get("exporter"), Format: values.Get("format"), Domain: &id, TimeBasis: values.Get("timeBasis"), Host: values.Get("host"), GroupBy: values.Get("groupBy"), Limit: 100}
	if q.TimeBasis == "" {
		q.TimeBasis = "flow"
	}
	if q.GroupBy == "" {
		q.GroupBy = "srcIP"
	}
	if values.Has("limit") {
		q.Limit, err = strconv.Atoi(values.Get("limit"))
		if err != nil {
			return q, fmt.Errorf("invalid limit")
		}
	}
	return q, nil
}

func (s *Server) handleFlowExportQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q, err := parseExportQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, _ := s.resolveOutDirFromRequest(r)
	if out == "" {
		http.Error(w, "No selected analysis dataset", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := flowexport.ReadReport(ctx, filepath.Join(out, "FlowExports.jsonl"), q)
	if err != nil {
		http.Error(w, "Export query unavailable: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(result)
}
