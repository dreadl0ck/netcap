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

// handleServicesTopByTraffic returns HTML for bar chart showing top services by traffic
func (s *Server) handleServicesTopByTraffic(w http.ResponseWriter, r *http.Request) {
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

	chart := generateServicesTopByTrafficChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleServicesProtocols returns HTML for pie chart showing protocol distribution
func (s *Server) handleServicesProtocols(w http.ResponseWriter, r *http.Request) {
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

	chart := generateServicesProtocolsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleServicesTopPorts returns HTML for bar chart showing top service ports
func (s *Server) handleServicesTopPorts(w http.ResponseWriter, r *http.Request) {
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

	chart := generateServicesTopPortsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleServicesTopProducts returns HTML for bar chart showing top products
func (s *Server) handleServicesTopProducts(w http.ResponseWriter, r *http.Request) {
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

	chart := generateServicesTopProductsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateServicesTopByTrafficChart creates a bar chart showing top services by traffic
func generateServicesTopByTrafficChart(outDir string, showLegend bool) *charts.Bar {
	services, err := readServices(outDir)
	if err != nil {
		services = []ServiceSummary{}
	}

	// Take top 20 services
	limit := 20
	if len(services) < limit {
		limit = len(services)
	}
	topServices := services[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topServices))
	flowsData := make([]opts.BarData, 0, len(topServices))
	bytesData := make([]opts.BarData, 0, len(topServices))

	for _, svc := range topServices {
		label := fmt.Sprintf("%s:%d", svc.IP, svc.Port)
		if svc.PortName != "" {
			label = fmt.Sprintf("%s:%d (%s)", svc.IP, svc.Port, svc.PortName)
		}
		if len(label) > 40 {
			// Truncate long labels
			label = label[:37] + "..."
		}
		xAxis = append(xAxis, label)
		flowsData = append(flowsData, opts.BarData{Value: svc.NumFlows})
		totalBytes := (svc.BytesServer + svc.BytesClient) / 1024 // Convert to KB
		bytesData = append(bytesData, opts.BarData{Value: totalBytes})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Services by Traffic",
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
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Flows", flowsData).
		AddSeries("Bytes (KB)", bytesData)

	return bar
}

// generateServicesProtocolsChart creates a pie chart showing protocol distribution
func generateServicesProtocolsChart(outDir string, showLegend bool) *charts.Pie {
	services, err := readServices(outDir)
	if err != nil {
		services = []ServiceSummary{}
	}

	// Aggregate protocols
	protoCount := make(map[string]int)
	for _, svc := range services {
		proto := svc.Protocol
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

// generateServicesTopPortsChart creates a bar chart showing top service ports
func generateServicesTopPortsChart(outDir string, showLegend bool) *charts.Bar {
	services, err := readServices(outDir)
	if err != nil {
		services = []ServiceSummary{}
	}

	// Aggregate ports with their names
	type portInfo struct {
		port     int32
		portName string
		count    int
	}
	portMap := make(map[int32]*portInfo)
	for _, svc := range services {
		if _, exists := portMap[svc.Port]; !exists {
			portMap[svc.Port] = &portInfo{
				port:     svc.Port,
				portName: svc.PortName,
				count:    0,
			}
		}
		portMap[svc.Port].count++
	}

	// Convert to slice
	ports := make([]*portInfo, 0, len(portMap))
	for _, info := range portMap {
		ports = append(ports, info)
	}

	// Sort by count descending
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j].count > ports[i].count {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}

	// Take top 20
	limit := 20
	if len(ports) < limit {
		limit = len(ports)
	}
	topPorts := ports[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topPorts))
	barData := make([]opts.BarData, 0, len(topPorts))

	for _, port := range topPorts {
		label := fmt.Sprintf("%d", port.port)
		if port.portName != "" {
			label = fmt.Sprintf("%d (%s)", port.port, port.portName)
		}
		xAxis = append(xAxis, label)
		barData = append(barData, opts.BarData{Value: port.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Service Ports",
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
			Name: "Service Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Services", barData)

	return bar
}

// generateServicesTopProductsChart creates a bar chart showing top products
func generateServicesTopProductsChart(outDir string, showLegend bool) *charts.Bar {
	services, err := readServices(outDir)
	if err != nil {
		services = []ServiceSummary{}
	}

	// Aggregate products
	productCount := make(map[string]int)
	for _, svc := range services {
		if svc.Product != "" {
			// Create a combined label with vendor if available
			label := svc.Product
			if svc.Vendor != "" && svc.Vendor != svc.Product {
				label = svc.Vendor + " " + svc.Product
			}
			productCount[label]++
		}
	}

	// Convert to sortable slice
	type productPair struct {
		name  string
		count int
	}
	products := make([]productPair, 0, len(productCount))
	for name, count := range productCount {
		products = append(products, productPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(products); i++ {
		for j := i + 1; j < len(products); j++ {
			if products[j].count > products[i].count {
				products[i], products[j] = products[j], products[i]
			}
		}
	}

	// Take top 20
	limit := 20
	if len(products) < limit {
		limit = len(products)
	}
	topProducts := products[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topProducts))
	barData := make([]opts.BarData, 0, len(topProducts))

	for _, product := range topProducts {
		label := product.name
		if len(label) > 30 {
			label = label[:27] + "..."
		}
		xAxis = append(xAxis, label)
		barData = append(barData, opts.BarData{Value: product.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Service Products",
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
			Name: "Service Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Services", barData)

	return bar
}
