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

// handleHostsTopTalkers returns HTML for bar chart showing top hosts by traffic
func (s *Server) handleHostsTopTalkers(w http.ResponseWriter, r *http.Request) {
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

	chart := generateHostsTopTalkersChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleHostsTrafficDistribution returns HTML for pie chart showing internal vs external traffic
func (s *Server) handleHostsTrafficDistribution(w http.ResponseWriter, r *http.Request) {
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

	chart := generateHostsTrafficDistributionChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleHostsApplications returns HTML for bar chart showing top applications
func (s *Server) handleHostsApplications(w http.ResponseWriter, r *http.Request) {
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

	chart := generateHostsApplicationsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleHostsProtocols returns HTML for sunburst chart showing protocol distribution
func (s *Server) handleHostsProtocols(w http.ResponseWriter, r *http.Request) {
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

	// Parse showLegend parameter (default to true)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr != "false"

	chart := generateHostsProtocolsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateHostsTopTalkersChart creates a bar chart showing top hosts by traffic
func generateHostsTopTalkersChart(outDir string, showLegend bool) *charts.Bar {
	hosts, err := readIPProfiles(outDir)
	if err != nil {
		hosts = []IPProfileSummary{}
	}

	// Take top 20 hosts
	limit := 20
	if len(hosts) < limit {
		limit = len(hosts)
	}
	topHosts := hosts[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topHosts))
	packetsData := make([]opts.BarData, 0, len(topHosts))
	bytesData := make([]opts.BarData, 0, len(topHosts))

	for _, host := range topHosts {
		xAxis = append(xAxis, host.Addr)
		packetsData = append(packetsData, opts.BarData{Value: host.NumPackets})
		bytesData = append(bytesData, opts.BarData{Value: host.Bytes / 1024}) // Convert to KB
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Hosts by Traffic",
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
			Name: "Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "20%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Packets", packetsData).
		AddSeries("Bytes (KB)", bytesData)

	return bar
}

// generateHostsTrafficDistributionChart creates a pie chart showing internal vs external traffic
func generateHostsTrafficDistributionChart(outDir string, showLegend bool) *charts.Pie {
	hosts, err := readIPProfiles(outDir)
	if err != nil {
		hosts = []IPProfileSummary{}
	}

	// Aggregate internal vs external traffic
	var internalPackets, externalPackets int64
	var internalBytes, externalBytes uint64

	for _, host := range hosts {
		if host.IsInternal {
			internalPackets += host.NumPackets
			internalBytes += host.Bytes
		} else {
			externalPackets += host.NumPackets
			externalBytes += host.Bytes
		}
	}

	// Prepare data
	pieData := make([]opts.PieData, 0, 4)
	pieData = append(pieData, opts.PieData{
		Name:  "Internal Packets",
		Value: internalPackets,
	})
	pieData = append(pieData, opts.PieData{
		Name:  "External Packets",
		Value: externalPackets,
	})
	pieData = append(pieData, opts.PieData{
		Name:  "Internal Bytes",
		Value: internalBytes / 1024, // Convert to KB
	})
	pieData = append(pieData, opts.PieData{
		Name:  "External Bytes",
		Value: externalBytes / 1024, // Convert to KB
	})

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Traffic Distribution",
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

	pie.AddSeries("Traffic", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateHostsApplicationsChart creates a bar chart showing top applications
func generateHostsApplicationsChart(outDir string, showLegend bool) *charts.Bar {
	hosts, err := readIPProfiles(outDir)
	if err != nil {
		hosts = []IPProfileSummary{}
	}

	// Aggregate applications
	appCount := make(map[string]int)
	for _, host := range hosts {
		for _, app := range host.Applications {
			if app != "" {
				appCount[app]++
			}
		}
	}

	// Convert to sortable slice
	type appPair struct {
		name  string
		count int
	}
	apps := make([]appPair, 0, len(appCount))
	for name, count := range appCount {
		apps = append(apps, appPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(apps); i++ {
		for j := i + 1; j < len(apps); j++ {
			if apps[j].count > apps[i].count {
				apps[i], apps[j] = apps[j], apps[i]
			}
		}
	}

	// Take top 20
	limit := 20
	if len(apps) < limit {
		limit = len(apps)
	}
	topApps := apps[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topApps))
	barData := make([]opts.BarData, 0, len(topApps))

	for _, app := range topApps {
		xAxis = append(xAxis, app.name)
		barData = append(barData, opts.BarData{Value: app.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Applications",
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
			Name: "Host Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Hosts", barData)

	return bar
}

// generateHostsProtocolsChart creates a sunburst chart showing protocol distribution
func generateHostsProtocolsChart(outDir string, showLegend bool) *charts.Sunburst {
	hosts, err := readIPProfiles(outDir)
	if err != nil {
		hosts = []IPProfileSummary{}
	}

	// Aggregate protocols by category
	categoryProtos := make(map[string]map[string]uint64)

	for _, host := range hosts {
		for _, proto := range host.TopProtocols {
			category := proto.Category
			if category == "" {
				category = "Uncategorized"
			}

			if categoryProtos[category] == nil {
				categoryProtos[category] = make(map[string]uint64)
			}
			categoryProtos[category][proto.Name] += proto.Packets
		}
	}

	// Build sunburst data
	sunburstData := make([]opts.SunBurstData, 0)

	for category, protos := range categoryProtos {
		children := make([]*opts.SunBurstData, 0)
		for name, packets := range protos {
			children = append(children, &opts.SunBurstData{
				Name:  name,
				Value: float64(packets),
			})
		}

		// Calculate category total
		var categoryTotal uint64
		for _, packets := range protos {
			categoryTotal += packets
		}

		sunburstData = append(sunburstData, opts.SunBurstData{
			Name:     category,
			Value:    float64(categoryTotal),
			Children: children,
		})
	}

	sunburst := charts.NewSunburst()
	sunburst.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Protocol Distribution",
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
			Right:  "10",
			Top:    "middle",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	sunburst.AddSeries("Protocols", sunburstData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:  opts.Bool(true),
				Color: "#ffffff",
			}),
		)

	return sunburst
}
