/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package webui

import (
	"bytes"
	"log"
	"net/http"
	"sort"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// handleHTTPTopHosts returns HTML for bar chart showing top hosts by request count
func (s *Server) handleHTTPTopHosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	httpRecords, err := readHTTP(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read HTTP records for chart: %v", err)
		http.Error(w, "Failed to read HTTP records", http.StatusInternalServerError)
		return
	}

	// Count requests per host
	hostCounts := make(map[string]int)
	for _, h := range httpRecords {
		if h.Host != "" {
			hostCounts[h.Host]++
		}
	}

	// Sort by count
	type hostCount struct {
		host  string
		count int
	}
	hostList := make([]hostCount, 0, len(hostCounts))
	for host, count := range hostCounts {
		hostList = append(hostList, hostCount{host, count})
	}
	sort.Slice(hostList, func(i, j int) bool {
		return hostList[i].count > hostList[j].count
	})

	// Take top 20
	limit := 20
	if len(hostList) < limit {
		limit = len(hostList)
	}
	hostList = hostList[:limit]

	// Prepare chart data
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "Top HTTP Hosts",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{
				Rotate: 45,
				Inside: opts.Bool(false),
			},
		}),
	)

	xAxis := make([]string, len(hostList))
	yAxis := make([]opts.BarData, len(hostList))

	for i, hc := range hostList {
		xAxis[i] = hc.host
		yAxis[i] = opts.BarData{Value: hc.count}
	}

	bar.SetXAxis(xAxis).AddSeries("Requests", yAxis)

	var buf bytes.Buffer
	bar.Render(&buf)
	html := buf.Bytes()

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleHTTPStatusCodes returns HTML for pie chart showing status code distribution
func (s *Server) handleHTTPStatusCodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	httpRecords, err := readHTTP(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read HTTP records for chart: %v", err)
		http.Error(w, "Failed to read HTTP records", http.StatusInternalServerError)
		return
	}

	// Count status code groups
	statusGroups := make(map[string]int)
	for _, h := range httpRecords {
		if h.StatusCode >= 200 && h.StatusCode < 300 {
			statusGroups["2xx Success"]++
		} else if h.StatusCode >= 300 && h.StatusCode < 400 {
			statusGroups["3xx Redirect"]++
		} else if h.StatusCode >= 400 && h.StatusCode < 500 {
			statusGroups["4xx Client Error"]++
		} else if h.StatusCode >= 500 {
			statusGroups["5xx Server Error"]++
		} else {
			statusGroups["Other"]++
		}
	}

	// Prepare chart data
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "HTTP Status Code Distribution",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
		}),
	)

	pieData := make([]opts.PieData, 0, len(statusGroups))
	for status, count := range statusGroups {
		pieData = append(pieData, opts.PieData{
			Name:  status,
			Value: count,
		})
	}

	pie.AddSeries("Status Codes", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c}",
			}),
		)

	var buf bytes.Buffer
	pie.Render(&buf)
	html := buf.Bytes()

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleHTTPMethods returns HTML for bar chart showing HTTP method distribution
func (s *Server) handleHTTPMethods(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	httpRecords, err := readHTTP(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read HTTP records for chart: %v", err)
		http.Error(w, "Failed to read HTTP records", http.StatusInternalServerError)
		return
	}

	// Count methods
	methodCounts := make(map[string]int)
	for _, h := range httpRecords {
		if h.Method != "" {
			methodCounts[h.Method]++
		}
	}

	// Sort by count
	type methodCount struct {
		method string
		count  int
	}
	methodList := make([]methodCount, 0, len(methodCounts))
	for method, count := range methodCounts {
		methodList = append(methodList, methodCount{method, count})
	}
	sort.Slice(methodList, func(i, j int) bool {
		return methodList[i].count > methodList[j].count
	})

	// Prepare chart data
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "HTTP Request Methods",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
	)

	xAxis := make([]string, len(methodList))
	yAxis := make([]opts.BarData, len(methodList))

	for i, mc := range methodList {
		xAxis[i] = mc.method
		yAxis[i] = opts.BarData{Value: mc.count}
	}

	bar.SetXAxis(xAxis).AddSeries("Requests", yAxis)

	var buf bytes.Buffer
	bar.Render(&buf)
	html := buf.Bytes()

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleHTTPContentTypes returns HTML for pie chart showing content type distribution
func (s *Server) handleHTTPContentTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	httpRecords, err := readHTTP(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read HTTP records for chart: %v", err)
		http.Error(w, "Failed to read HTTP records", http.StatusInternalServerError)
		return
	}

	// Count content types (simplified)
	contentTypeCounts := make(map[string]int)
	for _, h := range httpRecords {
		if h.ContentType != "" {
			// Simplify content type to just the main type
			ct := h.ContentType
			if idx := len(ct); idx > 0 {
				// Extract just the main part (before semicolon)
				if semiIdx := 0; semiIdx < len(ct) {
					for i, c := range ct {
						if c == ';' {
							ct = ct[:i]
							break
						}
					}
				}
				contentTypeCounts[ct]++
			}
		} else {
			contentTypeCounts["unknown"]++
		}
	}

	// Sort by count and take top 15
	type ctCount struct {
		contentType string
		count       int
	}
	ctList := make([]ctCount, 0, len(contentTypeCounts))
	for ct, count := range contentTypeCounts {
		ctList = append(ctList, ctCount{ct, count})
	}
	sort.Slice(ctList, func(i, j int) bool {
		return ctList[i].count > ctList[j].count
	})

	// Limit to top 15
	limit := 15
	if len(ctList) < limit {
		limit = len(ctList)
	}
	ctList = ctList[:limit]

	// Prepare chart data
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title: "HTTP Content Types",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(false),
			Orient: "vertical",
			Left:   "left",
		}),
	)

	pieData := make([]opts.PieData, len(ctList))
	for i, ct := range ctList {
		pieData[i] = opts.PieData{
			Name:  ct.contentType,
			Value: ct.count,
		}
	}

	pie.AddSeries("Content Types", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c}",
			}),
		)

	var buf bytes.Buffer
	pie.Render(&buf)
	html := buf.Bytes()

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

