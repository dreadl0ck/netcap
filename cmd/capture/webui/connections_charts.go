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
	"net/http"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// handleConnectionsTopByTraffic returns HTML for bar chart showing top connections by traffic
func (s *Server) handleConnectionsTopByTraffic(w http.ResponseWriter, r *http.Request) {
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

	chart := generateConnectionsTopByTrafficChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleConnectionsProtocols returns HTML for pie chart showing protocol distribution
func (s *Server) handleConnectionsProtocols(w http.ResponseWriter, r *http.Request) {
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

	chart := generateConnectionsProtocolsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleConnectionsApplications returns HTML for bar chart showing top applications
func (s *Server) handleConnectionsApplications(w http.ResponseWriter, r *http.Request) {
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

	chart := generateConnectionsApplicationsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleConnectionsDuration returns HTML for scatter chart showing connection duration vs size
func (s *Server) handleConnectionsDuration(w http.ResponseWriter, r *http.Request) {
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

	chart := generateConnectionsDurationChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateConnectionsTopByTrafficChart creates a bar chart showing top connections by traffic
func generateConnectionsTopByTrafficChart(outDir string, showLegend bool) *charts.Bar {
	connections, err := readConnections(outDir)
	if err != nil {
		connections = []ConnectionSummary{}
	}

	// Take top 20 connections
	limit := 20
	if len(connections) < limit {
		limit = len(connections)
	}
	topConnections := connections[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topConnections))
	packetsData := make([]opts.BarData, 0, len(topConnections))
	bytesData := make([]opts.BarData, 0, len(topConnections))

	for _, conn := range topConnections {
		label := conn.SrcIP + ":" + conn.SrcPort + " → " + conn.DstIP + ":" + conn.DstPort
		if len(label) > 40 {
			// Truncate long labels
			label = label[:37] + "..."
		}
		xAxis = append(xAxis, label)
		packetsData = append(packetsData, opts.BarData{Value: conn.NumPackets})
		bytesData = append(bytesData, opts.BarData{Value: conn.TotalSize / 1024}) // Convert to KB
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Connections by Traffic",
			Subtitle: "Packets and Bytes Transferred",
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
		AddSeries("Packets", packetsData).
		AddSeries("Bytes (KB)", bytesData)

	return bar
}

// generateConnectionsProtocolsChart creates a pie chart showing protocol distribution
func generateConnectionsProtocolsChart(outDir string, showLegend bool) *charts.Pie {
	connections, err := readConnections(outDir)
	if err != nil {
		connections = []ConnectionSummary{}
	}

	// Aggregate protocols (use TransportProto or ApplicationProto)
	protoCount := make(map[string]int)
	for _, conn := range connections {
		proto := conn.TransportProto
		if conn.ApplicationProto != "" {
			proto = conn.ApplicationProto
		}
		if proto == "" {
			proto = "Unknown"
		}
		protoCount[proto]++
	}

	// Convert to sortable slice
	type protoPair struct {
		name  string
		count int
	}
	protos := make([]protoPair, 0, len(protoCount))
	for name, count := range protoCount {
		protos = append(protos, protoPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(protos); i++ {
		for j := i + 1; j < len(protos); j++ {
			if protos[j].count > protos[i].count {
				protos[i], protos[j] = protos[j], protos[i]
			}
		}
	}

	// Prepare data (top 10 + "Other")
	pieData := make([]opts.PieData, 0)
	limit := 10
	otherCount := 0
	for i, proto := range protos {
		if i < limit {
			pieData = append(pieData, opts.PieData{
				Name:  proto.name,
				Value: proto.count,
			})
		} else {
			otherCount += proto.count
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
			Title:    "Protocol Distribution",
			Subtitle: "Application and Transport",
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

	pie.AddSeries("Protocols", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateConnectionsApplicationsChart creates a bar chart showing top applications
func generateConnectionsApplicationsChart(outDir string, showLegend bool) *charts.Bar {
	connections, err := readConnections(outDir)
	if err != nil {
		connections = []ConnectionSummary{}
	}

	// Aggregate applications
	appCount := make(map[string]int)
	for _, conn := range connections {
		for _, app := range conn.Applications {
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
			Subtitle: "Detected by DPI",
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
			Name: "Connection Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Connections", barData)

	return bar
}

// generateConnectionsDurationChart creates a scatter chart showing connection duration vs size
func generateConnectionsDurationChart(outDir string, showLegend bool) *charts.Scatter {
	connections, err := readConnections(outDir)
	if err != nil {
		connections = []ConnectionSummary{}
	}

	// Prepare scatter data: [duration (seconds), size (KB)]
	// Limit to reasonable sample size for performance
	limit := 1000
	if len(connections) < limit {
		limit = len(connections)
	}
	sampleConns := connections[:limit]

	scatterData := make([]opts.ScatterData, 0, len(sampleConns))
	for _, conn := range sampleConns {
		durationSeconds := float64(conn.Duration) / 1e9 // Convert nanoseconds to seconds
		sizeKB := float64(conn.TotalSize) / 1024
		scatterData = append(scatterData, opts.ScatterData{
			Value: []interface{}{durationSeconds, sizeKB},
		})
	}

	scatter := charts.NewScatter()
	scatter.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Connection Duration vs Size",
			Subtitle: "Relationship between duration and data transferred",
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
			Name: "Duration (seconds)",
			Type: "value",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Name: "Size (KB)",
			Type: "value",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
	)

	scatter.AddSeries("Connections", scatterData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:  opts.Bool(false),
				Color: "#ffffff",
			}),
		)

	return scatter
}

