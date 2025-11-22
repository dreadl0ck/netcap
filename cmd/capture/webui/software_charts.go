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
	"strings"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

// handleSoftwareTopProducts returns HTML for bar chart showing top software products
func (s *Server) handleSoftwareTopProducts(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSoftwareTopProductsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleSoftwareVendors returns HTML for pie chart showing vendor distribution
func (s *Server) handleSoftwareVendors(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSoftwareVendorsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleSoftwareOperatingSystems returns HTML for bar chart showing operating systems
func (s *Server) handleSoftwareOperatingSystems(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSoftwareOperatingSystemsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleSoftwareVersions returns HTML for sunburst chart showing product-version hierarchy
func (s *Server) handleSoftwareVersions(w http.ResponseWriter, r *http.Request) {
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

	chart := generateSoftwareVersionsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateSoftwareTopProductsChart creates a bar chart showing top software products
func generateSoftwareTopProductsChart(outDir string, showLegend bool) *charts.Bar {
	software, err := readSoftware(outDir)
	if err != nil {
		software = []SoftwareSummary{}
	}

	// Take top 20 software products
	limit := 20
	if len(software) < limit {
		limit = len(software)
	}
	topSoftware := software[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topSoftware))
	countData := make([]opts.BarData, 0, len(topSoftware))
	devicesData := make([]opts.BarData, 0, len(topSoftware))

	for _, sw := range topSoftware {
		label := sw.Product
		if sw.Version != "" {
			label += " " + sw.Version
		}
		if len(label) > 40 {
			label = label[:37] + "..."
		}
		xAxis = append(xAxis, label)
		countData = append(countData, opts.BarData{Value: sw.Count})
		devicesData = append(devicesData, opts.BarData{Value: len(sw.Devices)})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Software Products",
			Subtitle: "Most detected software and versions",
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
		AddSeries("Detections", countData).
		AddSeries("Devices", devicesData)

	return bar
}

// generateSoftwareVendorsChart creates a pie chart showing vendor distribution
func generateSoftwareVendorsChart(outDir string, showLegend bool) *charts.Pie {
	software, err := readSoftware(outDir)
	if err != nil {
		software = []SoftwareSummary{}
	}

	// Aggregate by vendor
	vendorCount := make(map[string]int)
	for _, sw := range software {
		vendor := sw.Vendor
		if vendor == "" {
			vendor = "Unknown"
		}
		vendorCount[vendor] += sw.Count
	}

	// Convert to sortable slice
	type vendorPair struct {
		name  string
		count int
	}
	vendors := make([]vendorPair, 0, len(vendorCount))
	for name, count := range vendorCount {
		vendors = append(vendors, vendorPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(vendors); i++ {
		for j := i + 1; j < len(vendors); j++ {
			if vendors[j].count > vendors[i].count {
				vendors[i], vendors[j] = vendors[j], vendors[i]
			}
		}
	}

	// Prepare data (top 10 + "Other")
	pieData := make([]opts.PieData, 0)
	limit := 10
	otherCount := 0
	for i, vendor := range vendors {
		if i < limit {
			pieData = append(pieData, opts.PieData{
				Name:  vendor.name,
				Value: vendor.count,
			})
		} else {
			otherCount += vendor.count
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
			Title:    "Software Vendors",
			Subtitle: "Distribution by detection count",
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

	pie.AddSeries("Vendors", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateSoftwareOperatingSystemsChart creates a bar chart showing operating systems
func generateSoftwareOperatingSystemsChart(outDir string, showLegend bool) *charts.Bar {
	software, err := readSoftware(outDir)
	if err != nil {
		software = []SoftwareSummary{}
	}

	// Aggregate by OS
	osCount := make(map[string]int)
	for _, sw := range software {
		os := sw.OS
		if os == "" {
			os = "Unknown"
		}
		osCount[os] += sw.Count
	}

	// Convert to sortable slice
	type osPair struct {
		name  string
		count int
	}
	operatingSystems := make([]osPair, 0, len(osCount))
	for name, count := range osCount {
		operatingSystems = append(operatingSystems, osPair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(operatingSystems); i++ {
		for j := i + 1; j < len(operatingSystems); j++ {
			if operatingSystems[j].count > operatingSystems[i].count {
				operatingSystems[i], operatingSystems[j] = operatingSystems[j], operatingSystems[i]
			}
		}
	}

	// Take top 15
	limit := 15
	if len(operatingSystems) < limit {
		limit = len(operatingSystems)
	}
	topOS := operatingSystems[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topOS))
	barData := make([]opts.BarData, 0, len(topOS))

	for _, os := range topOS {
		xAxis = append(xAxis, os.name)
		barData = append(barData, opts.BarData{Value: os.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Operating Systems",
			Subtitle: "Detected from Software",
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
			Name: "Detection Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Detections", barData)

	return bar
}

// generateSoftwareVersionsChart creates a sunburst chart showing product-version hierarchy
func generateSoftwareVersionsChart(outDir string, showLegend bool) *charts.Sunburst {
	software, err := readSoftware(outDir)
	if err != nil {
		software = []SoftwareSummary{}
	}

	// Group by product, then by version
	productVersions := make(map[string]map[string]int)
	for _, sw := range software {
		product := sw.Product
		if product == "" {
			product = "Unknown"
		}
		version := sw.Version
		if version == "" {
			version = "Unknown Version"
		}

		if productVersions[product] == nil {
			productVersions[product] = make(map[string]int)
		}
		productVersions[product][version] += sw.Count
	}

	// Build sunburst data - limit to top 15 products
	type productTotal struct {
		product string
		total   int
	}
	productTotals := make([]productTotal, 0)
	for product, versions := range productVersions {
		total := 0
		for _, count := range versions {
			total += count
		}
		productTotals = append(productTotals, productTotal{product, total})
	}

	// Sort by total descending
	for i := 0; i < len(productTotals); i++ {
		for j := i + 1; j < len(productTotals); j++ {
			if productTotals[j].total > productTotals[i].total {
				productTotals[i], productTotals[j] = productTotals[j], productTotals[i]
			}
		}
	}

	// Take top 15 products
	limit := 15
	if len(productTotals) < limit {
		limit = len(productTotals)
	}

	sunburstData := make([]opts.SunBurstData, 0)
	for i := 0; i < limit; i++ {
		product := productTotals[i].product
		versions := productVersions[product]

		children := make([]*opts.SunBurstData, 0)
		for version, count := range versions {
			children = append(children, &opts.SunBurstData{
				Name:  version,
				Value: float64(count),
			})
		}

		sunburstData = append(sunburstData, opts.SunBurstData{
			Name:     product,
			Value:    float64(productTotals[i].total),
			Children: children,
		})
	}

	sunburst := charts.NewSunburst()
	sunburst.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Software Versions",
			Subtitle: "Product and Version Hierarchy",
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

	sunburst.AddSeries("Software", sunburstData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:  opts.Bool(true),
				Color: "#ffffff",
			}),
		)

	return sunburst
}

// extractOSFamily returns a simplified OS family name
func extractOSFamily(os string) string {
	osLower := strings.ToLower(os)
	if strings.Contains(osLower, "windows") {
		return "Windows"
	}
	if strings.Contains(osLower, "linux") {
		return "Linux"
	}
	if strings.Contains(osLower, "mac") || strings.Contains(osLower, "osx") {
		return "macOS"
	}
	if strings.Contains(osLower, "ios") {
		return "iOS"
	}
	if strings.Contains(osLower, "android") {
		return "Android"
	}
	if strings.Contains(osLower, "unix") || strings.Contains(osLower, "bsd") {
		return "Unix/BSD"
	}
	if os != "" {
		return os
	}
	return "Unknown"
}
