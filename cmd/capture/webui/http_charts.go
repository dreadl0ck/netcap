/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package webui

import (
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
	limit := min(len(hostList), 20)
	hostList = hostList[:limit]

	// Check if legend should be shown
	showLegend := r.URL.Query().Get("showLegend") != "false"

	// Prepare chart data
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top HTTP Hosts",
			Subtitle: "",
			Left:     "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
			SubtitleStyle: &opts.TextStyle{
				Color: "#cccccc",
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(showLegend),
			Top:  "8%",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{
				Rotate: 45,
				Color:  "#ffffff",
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Requests",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Left:         "3%",
			Right:        "4%",
			Bottom:       "15%",
			ContainLabel: opts.Bool(true),
		}),
	)

	xAxis := make([]string, len(hostList))
	yAxis := make([]opts.BarData, len(hostList))

	for i, hc := range hostList {
		xAxis[i] = hc.host
		yAxis[i] = opts.BarData{Value: hc.count}
	}

	bar.SetXAxis(xAxis).AddSeries("Requests", yAxis)

	html, err := injectFullHeightCSS(bar.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

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

	// Check if legend should be shown
	showLegend := r.URL.Query().Get("showLegend") != "false"

	// Prepare chart data
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "HTTP Status Code Distribution",
			Subtitle: "",
			Left:     "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
			SubtitleStyle: &opts.TextStyle{
				Color: "#cccccc",
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Orient: "vertical",
			Left:   "left",
			Top:    "center",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
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
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	html, err := injectFullHeightCSS(pie.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

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

	// Check if legend should be shown
	showLegend := r.URL.Query().Get("showLegend") != "false"

	// Prepare chart data
	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "HTTP Request Methods",
			Subtitle: "",
			Left:     "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
			SubtitleStyle: &opts.TextStyle{
				Color: "#cccccc",
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "axis",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(showLegend),
			Top:  "8%",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Requests",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Left:         "3%",
			Right:        "4%",
			Bottom:       "3%",
			ContainLabel: opts.Bool(true),
		}),
	)

	xAxis := make([]string, len(methodList))
	yAxis := make([]opts.BarData, len(methodList))

	for i, mc := range methodList {
		xAxis[i] = mc.method
		yAxis[i] = opts.BarData{Value: mc.count}
	}

	bar.SetXAxis(xAxis).AddSeries("Requests", yAxis)

	html, err := injectFullHeightCSS(bar.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

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
	limit := min(len(ctList), 15)
	ctList = ctList[:limit]

	// Check if legend should be shown
	showLegend := r.URL.Query().Get("showLegend") != "false"

	// Prepare chart data
	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "HTTP Content Types",
			Subtitle: "",
			Left:     "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
			SubtitleStyle: &opts.TextStyle{
				Color: "#cccccc",
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Orient: "vertical",
			Left:   "left",
			Top:    "center",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
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
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	html, err := injectFullHeightCSS(pie.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}
