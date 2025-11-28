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

// handleFingerprintsTypeDistribution returns HTML for pie chart showing fingerprint type distribution
func (s *Server) handleFingerprintsTypeDistribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Parse showLegend parameter (default to true for pie charts)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr != "false"

	chart := generateFingerprintsTypeDistributionChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleFingerprintsTopJA3 returns HTML for bar chart showing top JA3 fingerprints
func (s *Server) handleFingerprintsTopJA3(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateFingerprintsTopJA3Chart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleFingerprintsTopHASSH returns HTML for bar chart showing top HASSH fingerprints
func (s *Server) handleFingerprintsTopHASSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateFingerprintsTopHASSHChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleFingerprintsHostsPerFingerprint returns HTML for scatter chart showing hosts per fingerprint
func (s *Server) handleFingerprintsHostsPerFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
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

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateFingerprintsHostsPerFingerprintChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateFingerprintsTypeDistributionChart creates a pie chart showing fingerprint type distribution
func generateFingerprintsTypeDistributionChart(outDir string, showLegend bool) *charts.Pie {
	fingerprints, err := readFingerprints(outDir)
	if err != nil {
		fingerprints = []FingerprintSummary{}
	}

	// Aggregate by type
	typeCount := make(map[string]int)
	for _, fp := range fingerprints {
		typeCount[fp.Type] += fp.Count
	}

	// Prepare data
	pieData := make([]opts.PieData, 0, len(typeCount))
	for fpType, count := range typeCount {
		pieData = append(pieData, opts.PieData{
			Name:  fpType,
			Value: count,
		})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Fingerprint Type Distribution",
			Subtitle: "JA3, HASSH, and DHCP",
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
			Right:  "10%",
			Top:    "center",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	pie.AddSeries("Fingerprints", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateFingerprintsTopJA3Chart creates a bar chart showing top JA3 fingerprints
func generateFingerprintsTopJA3Chart(outDir string, showLegend bool) *charts.Bar {
	fingerprints, err := readFingerprints(outDir)
	if err != nil {
		fingerprints = []FingerprintSummary{}
	}

	// Filter JA3 fingerprints
	ja3Fingerprints := make([]FingerprintSummary, 0)
	for _, fp := range fingerprints {
		if fp.Type == "JA3" {
			ja3Fingerprints = append(ja3Fingerprints, fp)
		}
	}

	// Take top 15
	limit := 15
	if len(ja3Fingerprints) < limit {
		limit = len(ja3Fingerprints)
	}
	topFingerprints := ja3Fingerprints[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topFingerprints))
	countData := make([]opts.BarData, 0, len(topFingerprints))
	hostsData := make([]opts.BarData, 0, len(topFingerprints))

	for _, fp := range topFingerprints {
		label := fp.Fingerprint
		if len(label) > 16 {
			label = label[:13] + "..."
		}
		if fp.Description != "" {
			label = fp.Description
			if len(label) > 30 {
				label = label[:27] + "..."
			}
		}
		xAxis = append(xAxis, label)
		countData = append(countData, opts.BarData{Value: fp.Count})
		hostsData = append(hostsData, opts.BarData{Value: len(fp.Hosts)})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top JA3 Fingerprints",
			Subtitle: "TLS Client Fingerprints",
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
			Name: "Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Occurrences", countData).
		AddSeries("Hosts", hostsData)

	return bar
}

// generateFingerprintsTopHASSHChart creates a bar chart showing top HASSH fingerprints
func generateFingerprintsTopHASSHChart(outDir string, showLegend bool) *charts.Bar {
	fingerprints, err := readFingerprints(outDir)
	if err != nil {
		fingerprints = []FingerprintSummary{}
	}

	// Filter HASSH fingerprints
	hasshFingerprints := make([]FingerprintSummary, 0)
	for _, fp := range fingerprints {
		if fp.Type == "HASSH" {
			hasshFingerprints = append(hasshFingerprints, fp)
		}
	}

	// Take top 15
	limit := 15
	if len(hasshFingerprints) < limit {
		limit = len(hasshFingerprints)
	}
	topFingerprints := hasshFingerprints[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topFingerprints))
	countData := make([]opts.BarData, 0, len(topFingerprints))
	hostsData := make([]opts.BarData, 0, len(topFingerprints))

	for _, fp := range topFingerprints {
		label := fp.Fingerprint
		if len(label) > 16 {
			label = label[:13] + "..."
		}
		if fp.Description != "" {
			label = fp.Description
			if len(label) > 30 {
				label = label[:27] + "..."
			}
		}
		xAxis = append(xAxis, label)
		countData = append(countData, opts.BarData{Value: fp.Count})
		hostsData = append(hostsData, opts.BarData{Value: len(fp.Hosts)})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top HASSH Fingerprints",
			Subtitle: "SSH Client/Server Fingerprints",
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
			Name: "Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Occurrences", countData).
		AddSeries("Hosts", hostsData)

	return bar
}

// generateFingerprintsHostsPerFingerprintChart creates a scatter chart showing hosts per fingerprint
func generateFingerprintsHostsPerFingerprintChart(outDir string, showLegend bool) *charts.Scatter {
	fingerprints, err := readFingerprints(outDir)
	if err != nil {
		fingerprints = []FingerprintSummary{}
	}

	// Prepare scatter data: [occurrence count, unique hosts]
	scatterData := make([]opts.ScatterData, 0, len(fingerprints))
	for _, fp := range fingerprints {
		scatterData = append(scatterData, opts.ScatterData{
			Value: []interface{}{fp.Count, len(fp.Hosts)},
		})
	}

	scatter := charts.NewScatter()
	scatter.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Fingerprint Usage Patterns",
			Subtitle: "Occurrences vs Unique Hosts",
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
			Show: opts.Bool(showLegend),
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "Occurrences",
			Type: "value",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Unique Hosts",
			Type: "value",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
	)

	scatter.AddSeries("Fingerprints", scatterData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:  opts.Bool(false),
				Color: "#ffffff",
			}),
		)

	return scatter
}
