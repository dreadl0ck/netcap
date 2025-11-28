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
	"net/http"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// handleVulnerabilitiesSeverity returns HTML for pie chart showing vulnerability severity distribution
func (s *Server) handleVulnerabilitiesSeverity(w http.ResponseWriter, r *http.Request) {
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

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	showLegend := r.URL.Query().Get("showLegend") != "false"
	chart := generateVulnerabilitiesSeverityChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleVulnerabilitiesTopVulnerableSoftware returns HTML for bar chart
func (s *Server) handleVulnerabilitiesTopVulnerableSoftware(w http.ResponseWriter, r *http.Request) {
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

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	showLegend := r.URL.Query().Get("showLegend") == "true"
	chart := generateTopVulnerableSoftwareChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleVulnerabilitiesAccessVectors returns HTML for pie chart showing access vector distribution
func (s *Server) handleVulnerabilitiesAccessVectors(w http.ResponseWriter, r *http.Request) {
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

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	showLegend := r.URL.Query().Get("showLegend") != "false"
	chart := generateAccessVectorsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleVulnerabilitiesExploitTypes returns HTML for pie chart showing exploit type distribution
func (s *Server) handleVulnerabilitiesExploitTypes(w http.ResponseWriter, r *http.Request) {
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

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	showLegend := r.URL.Query().Get("showLegend") != "false"
	chart := generateExploitTypesChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleVulnerabilitiesTopAffectedHosts returns HTML for bar chart showing most affected hosts
func (s *Server) handleVulnerabilitiesTopAffectedHosts(w http.ResponseWriter, r *http.Request) {
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

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	showLegend := r.URL.Query().Get("showLegend") == "true"
	chart := generateTopAffectedHostsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateAccessVectorsChart creates a pie chart showing access vector distribution
func generateAccessVectorsChart(outDir string, showLegend bool) *charts.Pie {
	data, err := readVulnerabilitiesAndExploits(outDir)
	if err != nil {
		data = &VulnerabilitiesResponse{}
	}

	accessVectorCount := make(map[string]int)
	for _, v := range data.Vulnerabilities {
		av := v.AccessVector
		if av == "" {
			av = "Unknown"
		}
		accessVectorCount[av]++
	}

	pieData := make([]opts.PieData, 0)
	for k, v := range accessVectorCount {
		pieData = append(pieData, opts.PieData{Name: k, Value: v})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:      "Access Vectors",
			Left:       "center",
			TitleStyle: &opts.TextStyle{Color: "#ffffff"},
		}),
		charts.WithLegendOpts(opts.Legend{Show: opts.Bool(showLegend), TextStyle: &opts.TextStyle{Color: "#ffffff"}}),
	)
	pie.AddSeries("Access Vector", pieData).SetSeriesOptions(
		charts.WithLabelOpts(opts.Label{Show: opts.Bool(true), Formatter: "{b}: {c} ({d}%)", Color: "#ffffff"}),
	)
	return pie
}

// generateExploitTypesChart creates a pie chart showing exploit type distribution
func generateExploitTypesChart(outDir string, showLegend bool) *charts.Pie {
	data, err := readVulnerabilitiesAndExploits(outDir)
	if err != nil {
		data = &VulnerabilitiesResponse{}
	}

	typeCount := make(map[string]int)
	for _, e := range data.Exploits {
		t := e.Type
		if t == "" {
			t = "Unknown"
		}
		typeCount[t]++
	}

	pieData := make([]opts.PieData, 0)
	for k, v := range typeCount {
		pieData = append(pieData, opts.PieData{Name: k, Value: v})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:      "Exploit Types",
			Left:       "center",
			TitleStyle: &opts.TextStyle{Color: "#ffffff"},
		}),
		charts.WithLegendOpts(opts.Legend{Show: opts.Bool(showLegend), TextStyle: &opts.TextStyle{Color: "#ffffff"}}),
	)
	pie.AddSeries("Type", pieData).SetSeriesOptions(
		charts.WithLabelOpts(opts.Label{Show: opts.Bool(true), Formatter: "{b}: {c} ({d}%)", Color: "#ffffff"}),
	)
	return pie
}

// generateTopAffectedHostsChart creates a bar chart showing the most affected hosts
func generateTopAffectedHostsChart(outDir string, showLegend bool) *charts.Bar {
	data, err := readVulnerabilitiesAndExploits(outDir)
	if err != nil {
		data = &VulnerabilitiesResponse{}
	}

	// Convert to arrays for sorting
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for _, h := range data.AffectedHosts {
		// Total vulnerabilities + exploits for each host
		total := h.Vulnerabilities + h.Exploits
		if total > 0 {
			ss = append(ss, kv{h.Host, total})
		}
	}

	// Sort desc
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if ss[j].Value > ss[i].Value {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}

	// Top 10
	if len(ss) > 10 {
		ss = ss[:10]
	}

	xAxis := make([]string, len(ss))
	barData := make([]opts.BarData, len(ss))
	for i, item := range ss {
		xAxis[i] = item.Key
		barData[i] = opts.BarData{Value: item.Value}
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:      "Top Affected Hosts",
			Left:       "center",
			TitleStyle: &opts.TextStyle{Color: "#ffffff"},
		}),
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{Rotate: 45, Color: "#ffffff"},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			AxisLabel: &opts.AxisLabel{Color: "#ffffff"},
		}),
		charts.WithLegendOpts(opts.Legend{Show: opts.Bool(showLegend), TextStyle: &opts.TextStyle{Color: "#ffffff"}}),
	)
	bar.SetXAxis(xAxis).AddSeries("Issues", barData)
	return bar
}
func generateVulnerabilitiesSeverityChart(outDir string, showLegend bool) *charts.Pie {
	data, err := readVulnerabilitiesAndExploits(outDir)
	if err != nil {
		data = &VulnerabilitiesResponse{}
	}

	severityCount := make(map[string]int)
	for _, v := range data.Vulnerabilities {
		severity := v.Severity
		if severity == "" {
			severity = "Unknown"
		}
		severityCount[severity]++
	}

	pieData := make([]opts.PieData, 0)
	for k, v := range severityCount {
		pieData = append(pieData, opts.PieData{Name: k, Value: v})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:      "Vulnerability Severity",
			Left:       "center",
			TitleStyle: &opts.TextStyle{Color: "#ffffff"},
		}),
		charts.WithLegendOpts(opts.Legend{Show: opts.Bool(showLegend), TextStyle: &opts.TextStyle{Color: "#ffffff"}}),
	)
	pie.AddSeries("Severity", pieData).SetSeriesOptions(
		charts.WithLabelOpts(opts.Label{Show: opts.Bool(true), Formatter: "{b}: {c} ({d}%)", Color: "#ffffff"}),
	)
	return pie
}

// generateTopVulnerableSoftwareChart creates a bar chart
func generateTopVulnerableSoftwareChart(outDir string, showLegend bool) *charts.Bar {
	data, err := readVulnerabilitiesAndExploits(outDir)
	if err != nil {
		data = &VulnerabilitiesResponse{}
	}

	softwareVulns := make(map[string]int)
	for _, v := range data.Vulnerabilities {
		if v.Software != nil && v.Software.Product != "" {
			// Create a string representation of the software
			softwareKey := v.Software.Product
			if v.Software.Vendor != "" {
				softwareKey = v.Software.Vendor + " " + softwareKey
			}
			if v.Software.Version != "" {
				softwareKey += " " + v.Software.Version
			}
			softwareVulns[softwareKey]++
		}
	}

	// Convert to arrays for sorting
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range softwareVulns {
		ss = append(ss, kv{k, v})
	}
	// Sort desc
	for i := 0; i < len(ss); i++ {
		for j := i + 1; j < len(ss); j++ {
			if ss[j].Value > ss[i].Value {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}

	// Top 10
	if len(ss) > 10 {
		ss = ss[:10]
	}

	xAxis := make([]string, len(ss))
	barData := make([]opts.BarData, len(ss))
	for i, item := range ss {
		xAxis[i] = item.Key
		barData[i] = opts.BarData{Value: item.Value}
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:      "Top Vulnerable Software",
			Left:       "center",
			TitleStyle: &opts.TextStyle{Color: "#ffffff"},
		}),
		charts.WithXAxisOpts(opts.XAxis{
			AxisLabel: &opts.AxisLabel{Rotate: 45, Color: "#ffffff"},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			AxisLabel: &opts.AxisLabel{Color: "#ffffff"},
		}),
		charts.WithLegendOpts(opts.Legend{Show: opts.Bool(showLegend), TextStyle: &opts.TextStyle{Color: "#ffffff"}}),
	)
	bar.SetXAxis(xAxis).AddSeries("Vulnerabilities", barData)
	return bar
}
