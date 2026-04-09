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
	"fmt"
	"net/http"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// handleCertificatesTopIssuers returns HTML for bar chart showing top certificate issuers
func (s *Server) handleCertificatesTopIssuers(w http.ResponseWriter, r *http.Request) {
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

	chart := generateCertificatesTopIssuersChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleCertificatesStatusDistribution returns HTML for pie chart showing certificate status distribution
func (s *Server) handleCertificatesStatusDistribution(w http.ResponseWriter, r *http.Request) {
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

	chart := generateCertificatesStatusDistributionChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleCertificatesKeyAlgorithms returns HTML for bar chart showing key algorithm distribution
func (s *Server) handleCertificatesKeyAlgorithms(w http.ResponseWriter, r *http.Request) {
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

	chart := generateCertificatesKeyAlgorithmsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleCertificatesExpirationTimeline returns HTML for scatter chart showing certificate expiration timeline
func (s *Server) handleCertificatesExpirationTimeline(w http.ResponseWriter, r *http.Request) {
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

	chart := generateCertificatesExpirationTimelineChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateCertificatesTopIssuersChart creates a bar chart showing top certificate issuers
func generateCertificatesTopIssuersChart(outDir string, showLegend bool) *charts.Bar {
	certificates, err := readCertificates(outDir)
	if err != nil {
		certificates = []CertificateSummary{}
	}

	// Aggregate issuers
	issuerCount := make(map[string]int)
	for _, cert := range certificates {
		issuer := cert.IssuerCommonName
		if issuer == "" {
			issuer = "Unknown"
		}
		issuerCount[issuer]++
	}

	// Convert to sortable slice
	type issuerPair struct {
		name  string
		count int
	}
	issuers := make([]issuerPair, 0, len(issuerCount))
	for name, count := range issuerCount {
		issuers = append(issuers, issuerPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(issuers); i++ {
		for j := i + 1; j < len(issuers); j++ {
			if issuers[j].count > issuers[i].count {
				issuers[i], issuers[j] = issuers[j], issuers[i]
			}
		}
	}

	// Take top 20
	limit := min(len(issuers), 20)
	topIssuers := issuers[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topIssuers))
	barData := make([]opts.BarData, 0, len(topIssuers))

	for _, issuer := range topIssuers {
		label := issuer.name
		if len(label) > 40 {
			label = label[:37] + "..."
		}
		xAxis = append(xAxis, label)
		barData = append(barData, opts.BarData{Value: issuer.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Certificate Issuers",
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
			Name: "Certificate Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Certificates", barData)

	return bar
}

// generateCertificatesStatusDistributionChart creates a pie chart showing certificate status distribution
func generateCertificatesStatusDistributionChart(outDir string, showLegend bool) *charts.Pie {
	certificates, err := readCertificates(outDir)
	if err != nil {
		certificates = []CertificateSummary{}
	}

	// Count by status
	statusCount := make(map[string]int)
	for _, cert := range certificates {
		if cert.IsExpired {
			statusCount["Expired"]++
		} else if cert.IsNotYetValid {
			statusCount["Not Yet Valid"]++
		} else if cert.HasWeakSignature || cert.HasShortKeySize {
			statusCount["Weak Security"]++
		} else if cert.IsSelfSigned {
			statusCount["Self-Signed"]++
		} else if cert.DaysUntilExpiration < 30 {
			statusCount["Expiring Soon (<30 days)"]++
		} else {
			statusCount["Valid"]++
		}
	}

	// Prepare data
	pieData := make([]opts.PieData, 0)
	for status, count := range statusCount {
		pieData = append(pieData, opts.PieData{
			Name:  status,
			Value: count,
		})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Certificate Status Distribution",
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
			Right:  "10%",
			Top:    "center",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	pie.AddSeries("Status", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateCertificatesKeyAlgorithmsChart creates a bar chart showing public key algorithm distribution
func generateCertificatesKeyAlgorithmsChart(outDir string, showLegend bool) *charts.Bar {
	certificates, err := readCertificates(outDir)
	if err != nil {
		certificates = []CertificateSummary{}
	}

	// Aggregate algorithms with key size
	algoCount := make(map[string]int)
	for _, cert := range certificates {
		algo := cert.PublicKeyAlgorithm
		if algo == "" {
			algo = "Unknown"
		}
		// Include key size in the label
		label := algo
		if cert.PublicKeySize > 0 {
			label = fmt.Sprintf("%s (%d bits)", algo, cert.PublicKeySize)
		}
		algoCount[label]++
	}

	// Convert to sortable slice
	type algoPair struct {
		name  string
		count int
	}
	algos := make([]algoPair, 0, len(algoCount))
	for name, count := range algoCount {
		algos = append(algos, algoPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(algos); i++ {
		for j := i + 1; j < len(algos); j++ {
			if algos[j].count > algos[i].count {
				algos[i], algos[j] = algos[j], algos[i]
			}
		}
	}

	// Take top 15
	limit := min(len(algos), 15)
	topAlgos := algos[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topAlgos))
	barData := make([]opts.BarData, 0, len(topAlgos))

	for _, algo := range topAlgos {
		xAxis = append(xAxis, algo.name)
		barData = append(barData, opts.BarData{Value: algo.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Public Key Algorithms",
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
			Name: "Certificate Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Certificates", barData)

	return bar
}

// generateCertificatesExpirationTimelineChart creates a scatter chart showing certificate expiration timeline
func generateCertificatesExpirationTimelineChart(outDir string, showLegend bool) *charts.Scatter {
	certificates, err := readCertificates(outDir)
	if err != nil {
		certificates = []CertificateSummary{}
	}

	// Filter out expired certificates and prepare data
	// X-axis: Days until expiration, Y-axis: Seen count
	scatterData := make([]opts.ScatterData, 0)

	for _, cert := range certificates {
		// Skip expired or not yet valid certificates
		if cert.IsExpired || cert.IsNotYetValid {
			continue
		}

		// Only show certificates expiring within the next year
		if cert.DaysUntilExpiration > 365 {
			continue
		}

		scatterData = append(scatterData, opts.ScatterData{
			Value: []any{cert.DaysUntilExpiration, cert.SeenCount},
			// Add tooltip with subject name
			Name: cert.SubjectCommonName,
		})
	}

	scatter := charts.NewScatter()
	scatter.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Certificate Expiration Timeline",
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
			Show: opts.Bool(showLegend),
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "Days Until Expiration",
			Type: "value",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
			// Add visual zone for "expiring soon" (< 30 days)
			SplitLine: &opts.SplitLine{
				Show: opts.Bool(true),
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Times Seen",
			Type: "value",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
	)

	scatter.AddSeries("Certificates", scatterData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:  opts.Bool(false),
				Color: "#ffffff",
			}),
		)

	return scatter
}
