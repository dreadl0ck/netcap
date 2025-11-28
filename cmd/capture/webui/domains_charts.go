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
	"strings"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// handleDomainsTopByQueries returns HTML for bar chart showing top domains by query count
func (s *Server) handleDomainsTopByQueries(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDomainsTopByQueriesChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDomainsTLDs returns HTML for pie chart showing TLD distribution
func (s *Server) handleDomainsTLDs(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDomainsTLDsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDomainsRecordTypes returns HTML for bar chart showing DNS record type distribution
func (s *Server) handleDomainsRecordTypes(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDomainsRecordTypesChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDomainsSubdomainDistribution returns HTML for sunburst chart showing subdomain hierarchy
func (s *Server) handleDomainsSubdomainDistribution(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDomainsSubdomainDistributionChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateDomainsTopByQueriesChart creates a bar chart showing top domains by query count
func generateDomainsTopByQueriesChart(outDir string, showLegend bool) *charts.Bar {
	domains, err := readDomains(outDir)
	if err != nil {
		domains = []DomainSummary{}
	}

	// Take top 20 domains
	limit := 20
	if len(domains) < limit {
		limit = len(domains)
	}
	topDomains := domains[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topDomains))
	queriesData := make([]opts.BarData, 0, len(topDomains))
	clientsData := make([]opts.BarData, 0, len(topDomains))

	for _, domain := range topDomains {
		label := domain.Domain
		if len(label) > 40 {
			// Truncate long domain names
			label = label[:37] + "..."
		}
		xAxis = append(xAxis, label)
		queriesData = append(queriesData, opts.BarData{Value: domain.QueryCount})
		clientsData = append(clientsData, opts.BarData{Value: domain.UniqueClients})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Domains by Query Count",
			Subtitle: "Most queried domains and unique clients",
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
		AddSeries("Queries", queriesData).
		AddSeries("Unique Clients", clientsData)

	return bar
}

// generateDomainsTLDsChart creates a pie chart showing TLD distribution
func generateDomainsTLDsChart(outDir string, showLegend bool) *charts.Pie {
	domains, err := readDomains(outDir)
	if err != nil {
		domains = []DomainSummary{}
	}

	// Aggregate TLDs
	tldCount := make(map[string]int)
	for _, domain := range domains {
		parts := strings.Split(domain.Domain, ".")
		if len(parts) > 0 {
			tld := parts[len(parts)-1]
			tldCount[tld] += domain.QueryCount
		}
	}

	// Convert to sortable slice
	type tldPair struct {
		name  string
		count int
	}
	tlds := make([]tldPair, 0, len(tldCount))
	for name, count := range tldCount {
		tlds = append(tlds, tldPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(tlds); i++ {
		for j := i + 1; j < len(tlds); j++ {
			if tlds[j].count > tlds[i].count {
				tlds[i], tlds[j] = tlds[j], tlds[i]
			}
		}
	}

	// Prepare data (top 10 + "Other")
	pieData := make([]opts.PieData, 0)
	limit := 10
	otherCount := 0
	for i, tld := range tlds {
		if i < limit {
			pieData = append(pieData, opts.PieData{
				Name:  "." + tld.name,
				Value: tld.count,
			})
		} else {
			otherCount += tld.count
		}
	}
	if otherCount > 0 {
		pieData = append(pieData, opts.PieData{
			Name:  "Other",
			Value: otherCount,
		})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Level Domains (TLDs)",
			Subtitle: "Distribution by query count",
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

	pie.AddSeries("TLDs", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateDomainsRecordTypesChart creates a bar chart showing DNS record type distribution
func generateDomainsRecordTypesChart(outDir string, showLegend bool) *charts.Bar {
	domains, err := readDomains(outDir)
	if err != nil {
		domains = []DomainSummary{}
	}

	// Aggregate record types
	recordTypeCount := make(map[string]int)
	for _, domain := range domains {
		for _, rt := range domain.RecordTypes {
			if rt != "" {
				recordTypeCount[rt]++
			}
		}
	}

	// Convert to sortable slice
	type rtPair struct {
		name  string
		count int
	}
	recordTypes := make([]rtPair, 0, len(recordTypeCount))
	for name, count := range recordTypeCount {
		recordTypes = append(recordTypes, rtPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(recordTypes); i++ {
		for j := i + 1; j < len(recordTypes); j++ {
			if recordTypes[j].count > recordTypes[i].count {
				recordTypes[i], recordTypes[j] = recordTypes[j], recordTypes[i]
			}
		}
	}

	// Take top 15
	limit := 15
	if len(recordTypes) < limit {
		limit = len(recordTypes)
	}
	topRecordTypes := recordTypes[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topRecordTypes))
	barData := make([]opts.BarData, 0, len(topRecordTypes))

	for _, rt := range topRecordTypes {
		xAxis = append(xAxis, rt.name)
		barData = append(barData, opts.BarData{Value: rt.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "DNS Record Types",
			Subtitle: "Distribution of query types",
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
				Rotate: 0,
				Color:  "#ffffff",
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Query Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "15%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Queries", barData)

	return bar
}

// generateDomainsSubdomainDistributionChart creates a pie chart showing subdomain vs domain distribution
func generateDomainsSubdomainDistributionChart(outDir string, showLegend bool) *charts.Pie {
	domains, err := readDomains(outDir)
	if err != nil {
		domains = []DomainSummary{}
	}

	// Count subdomains vs root domains
	var subdomainQueries, rootDomainQueries int
	for _, domain := range domains {
		if domain.IsSubdomain {
			subdomainQueries += domain.QueryCount
		} else {
			rootDomainQueries += domain.QueryCount
		}
	}

	// Prepare data
	pieData := []opts.PieData{
		{Name: "Root Domains", Value: rootDomainQueries},
		{Name: "Subdomains", Value: subdomainQueries},
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Subdomain Distribution",
			Subtitle: "Root domains vs subdomains",
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

	pie.AddSeries("Domains", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}
