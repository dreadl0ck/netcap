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

// handleDevicesMACVendors returns HTML for bar chart showing top MAC vendors
func (s *Server) handleDevicesMACVendors(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDevicesMACVendorsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDevicesHardware returns HTML for bar chart showing top hardware/devices
func (s *Server) handleDevicesHardware(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDevicesHardwareChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDevicesOperatingSystems returns HTML for pie chart showing operating systems
func (s *Server) handleDevicesOperatingSystems(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDevicesOperatingSystemsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDevicesApplications returns HTML for bar chart showing top applications
func (s *Server) handleDevicesApplications(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDevicesApplicationsChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// handleDevicesTrafficDistribution returns HTML for pie chart showing device traffic distribution
func (s *Server) handleDevicesTrafficDistribution(w http.ResponseWriter, r *http.Request) {
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

	chart := generateDevicesTrafficDistributionChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// generateDevicesMACVendorsChart creates a bar chart showing top MAC vendors
func generateDevicesMACVendorsChart(outDir string, showLegend bool) *charts.Bar {
	devices, err := readDeviceProfiles(outDir)
	if err != nil {
		devices = []DeviceProfileSummary{}
	}

	// Aggregate MAC vendors
	vendorCount := make(map[string]int)
	for _, device := range devices {
		vendor := device.DeviceManufacturer
		if vendor == "" {
			vendor = "Unknown"
		}
		vendorCount[vendor]++
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

	// Take top 20
	limit := min(len(vendors), 20)
	topVendors := vendors[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topVendors))
	barData := make([]opts.BarData, 0, len(topVendors))

	for _, vendor := range topVendors {
		xAxis = append(xAxis, vendor.name)
		barData = append(barData, opts.BarData{Value: vendor.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top MAC Vendors",
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
			Name: "Device Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Devices", barData)

	return bar
}

// generateDevicesHardwareChart creates a bar chart showing top hardware/devices
func generateDevicesHardwareChart(outDir string, showLegend bool) *charts.Bar {
	devices, err := readDeviceProfiles(outDir)
	if err != nil {
		devices = []DeviceProfileSummary{}
	}

	// Aggregate device types
	deviceTypeCount := make(map[string]int)
	for _, device := range devices {
		for _, deviceType := range device.Devices {
			if deviceType != "" {
				deviceTypeCount[deviceType]++
			}
		}
	}

	// If no device types found, show a message
	if len(deviceTypeCount) == 0 {
		deviceTypeCount["No device types detected"] = 1
	}

	// Convert to sortable slice
	type devicePair struct {
		name  string
		count int
	}
	deviceTypes := make([]devicePair, 0, len(deviceTypeCount))
	for name, count := range deviceTypeCount {
		deviceTypes = append(deviceTypes, devicePair{name, count})
	}

	// Sort by count descending
	for i := 0; i < len(deviceTypes); i++ {
		for j := i + 1; j < len(deviceTypes); j++ {
			if deviceTypes[j].count > deviceTypes[i].count {
				deviceTypes[i], deviceTypes[j] = deviceTypes[j], deviceTypes[i]
			}
		}
	}

	// Take top 20
	limit := min(len(deviceTypes), 20)
	topDeviceTypes := deviceTypes[:limit]

	// Prepare data
	xAxis := make([]string, 0, len(topDeviceTypes))
	barData := make([]opts.BarData, 0, len(topDeviceTypes))

	for _, deviceType := range topDeviceTypes {
		xAxis = append(xAxis, deviceType.name)
		barData = append(barData, opts.BarData{Value: deviceType.count})
	}

	bar := charts.NewBar()
	bar.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Top Device Types",
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
		AddSeries("Devices", barData)

	return bar
}

// generateDevicesOperatingSystemsChart creates a pie chart showing operating systems
func generateDevicesOperatingSystemsChart(outDir string, showLegend bool) *charts.Pie {
	devices, err := readDeviceProfiles(outDir)
	if err != nil {
		devices = []DeviceProfileSummary{}
	}

	// Aggregate operating systems from device types
	osCount := make(map[string]int)
	for _, device := range devices {
		for _, deviceType := range device.Devices {
			if deviceType != "" {
				// Try to extract OS info from device type
				os := extractOSFromDeviceType(deviceType)
				osCount[os]++
			}
		}
	}

	// If no OS data, show a placeholder
	if len(osCount) == 0 {
		osCount["Unknown OS"] = 1
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

	// Prepare data
	pieData := make([]opts.PieData, 0, len(operatingSystems))
	for _, os := range operatingSystems {
		pieData = append(pieData, opts.PieData{
			Name:  os.name,
			Value: os.count,
		})
	}

	pie := charts.NewPie()
	pie.SetGlobalOptions(
		charts.WithInitializationOpts(getDefaultChartInit()),
		charts.WithTitleOpts(opts.Title{
			Title:    "Operating Systems",
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

	pie.AddSeries("Operating Systems", pieData).
		SetSeriesOptions(
			charts.WithLabelOpts(opts.Label{
				Show:      opts.Bool(true),
				Formatter: "{b}: {c} ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// generateDevicesApplicationsChart creates a bar chart showing top applications
func generateDevicesApplicationsChart(outDir string, showLegend bool) *charts.Bar {
	devices, err := readDeviceProfiles(outDir)
	if err != nil {
		devices = []DeviceProfileSummary{}
	}

	// Aggregate applications
	appCount := make(map[string]int)
	for _, device := range devices {
		for _, app := range device.Applications {
			if app != "" {
				appCount[app]++
			}
		}
	}

	// If no applications found, show a message
	if len(appCount) == 0 {
		appCount["No applications detected"] = 1
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
	limit := min(len(apps), 20)
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
			Name: "Device Count",
			AxisLabel: &opts.AxisLabel{
				Color: "#ffffff",
			},
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: "25%",
		}),
	)

	bar.SetXAxis(xAxis).
		AddSeries("Devices", barData)

	return bar
}

// generateDevicesTrafficDistributionChart creates a pie chart showing traffic distribution
func generateDevicesTrafficDistributionChart(outDir string, showLegend bool) *charts.Pie {
	devices, err := readDeviceProfiles(outDir)
	if err != nil {
		devices = []DeviceProfileSummary{}
	}

	// Take top 10 devices by traffic
	limit := min(len(devices), 10)
	topDevices := devices[:limit]

	// Prepare data
	pieData := make([]opts.PieData, 0, len(topDevices))
	for _, device := range topDevices {
		label := device.MacAddr
		if device.DeviceManufacturer != "" {
			label = device.DeviceManufacturer + " (" + device.MacAddr + ")"
		}
		pieData = append(pieData, opts.PieData{
			Name:  label,
			Value: device.Bytes / 1024, // Convert to KB
		})
	}

	// If no devices, show placeholder
	if len(pieData) == 0 {
		pieData = append(pieData, opts.PieData{
			Name:  "No devices",
			Value: 0,
		})
	}

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
				Formatter: "{b}: {c} KB ({d}%)",
				Color:     "#ffffff",
			}),
		)

	return pie
}

// extractOSFromDeviceType attempts to extract OS information from device type string
func extractOSFromDeviceType(deviceType string) string {
	deviceTypeLower := strings.ToLower(deviceType)

	// Check for common OS keywords
	if strings.Contains(deviceTypeLower, "windows") {
		return "Windows"
	}
	if strings.Contains(deviceTypeLower, "linux") {
		return "Linux"
	}
	if strings.Contains(deviceTypeLower, "macos") || strings.Contains(deviceTypeLower, "mac os") || strings.Contains(deviceTypeLower, "osx") {
		return "macOS"
	}
	if strings.Contains(deviceTypeLower, "ios") || strings.Contains(deviceTypeLower, "iphone") || strings.Contains(deviceTypeLower, "ipad") {
		return "iOS"
	}
	if strings.Contains(deviceTypeLower, "android") {
		return "Android"
	}
	if strings.Contains(deviceTypeLower, "ubuntu") {
		return "Ubuntu"
	}
	if strings.Contains(deviceTypeLower, "debian") {
		return "Debian"
	}
	if strings.Contains(deviceTypeLower, "centos") || strings.Contains(deviceTypeLower, "rhel") {
		return "CentOS/RHEL"
	}
	if strings.Contains(deviceTypeLower, "freebsd") {
		return "FreeBSD"
	}

	// If no specific OS found, return the device type itself or "Other"
	if deviceType != "" {
		return deviceType
	}
	return "Other"
}
