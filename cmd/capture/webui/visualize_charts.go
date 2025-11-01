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
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/go-echarts/go-echarts/v2/types"
)

// injectFullHeightCSS intercepts the chart HTML and injects CSS to make it fill 100% height
func injectFullHeightCSS(renderFunc func(w io.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	if err := renderFunc(&buf); err != nil {
		return nil, err
	}

	html := buf.String()

	// Inject CSS right after <head> tag to make html, body, and chart container 100% height
	// Target all possible containers including the .item div and echarts canvas
	cssInjection := `<head>
<style>
html, body {
	height: 100% !important;
	margin: 0 !important;
	padding: 0 !important;
	overflow: hidden !important;
	width: 100% !important;
}
#main, .item, .container, div[_echarts_instance_] {
	height: 100% !important;
	width: 100% !important;
	min-height: 100% !important;
}
body > div {
	height: 100% !important;
	width: 100% !important;
}
canvas {
	display: block !important;
}
</style>
<script>
// Force resize chart to fill viewport after load
window.addEventListener('load', function() {
	var charts = document.querySelectorAll('[_echarts_instance_]');
	charts.forEach(function(el) {
		if (el && el.style) {
			el.style.height = window.innerHeight + 'px';
			el.style.width = window.innerWidth + 'px';
		}
		// Trigger echarts resize
		if (window.echarts) {
			var chart = echarts.getInstanceByDom(el);
			if (chart) {
				setTimeout(function() {
					chart.resize({
						width: window.innerWidth,
						height: window.innerHeight
					});
				}, 100);
			}
		}
	});
});
// Resize on window resize
window.addEventListener('resize', function() {
	var charts = document.querySelectorAll('[_echarts_instance_]');
	charts.forEach(function(el) {
		if (el && el.style) {
			el.style.height = window.innerHeight + 'px';
			el.style.width = window.innerWidth + 'px';
		}
		if (window.echarts) {
			var chart = echarts.getInstanceByDom(el);
			if (chart) {
				chart.resize({
					width: window.innerWidth,
					height: window.innerHeight
				});
			}
		}
	});
});
</script>`

	html = strings.Replace(html, "<head>", cssInjection, 1)
	return []byte(html), nil
}

// handleVisualizeTreemap returns HTML for treemap chart of audit record types
func (s *Server) handleVisualizeTreemap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateTreemapChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeTreemap is an exported handler factory for service mode
func HandleVisualizeTreemap(outDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outDir == "" {
			http.Error(w, "No output directory set", http.StatusServiceUnavailable)
			return
		}

		// Parse showLegend parameter (default to false)
		showLegendStr := r.URL.Query().Get("showLegend")
		showLegend := showLegendStr == "true"

		chart := generateTreemapChart(outDir, showLegend)
		html, err := injectFullHeightCSS(chart.Render)
		if err != nil {
			http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(html)
	}
}

// handleVisualizeBar3D returns HTML for 3D bar chart of audit record types
func (s *Server) handleVisualizeBar3D(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	chart := generateBar3DChart(outDir)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeBar3D is an exported handler factory for service mode
func HandleVisualizeBar3D(outDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outDir == "" {
			http.Error(w, "No output directory set", http.StatusServiceUnavailable)
			return
		}

		chart := generateBar3DChart(outDir)
		html, err := injectFullHeightCSS(chart.Render)
		if err != nil {
			http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(html)
	}
}

// handleVisualizeGraph returns HTML for graph chart of audit record types
func (s *Server) handleVisualizeGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := generateGraphChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeGraph is an exported handler factory for service mode
func HandleVisualizeGraph(outDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if outDir == "" {
			http.Error(w, "No output directory set", http.StatusServiceUnavailable)
			return
		}

		// Parse showLegend parameter (default to false)
		showLegendStr := r.URL.Query().Get("showLegend")
		showLegend := showLegendStr == "true"

		chart := generateGraphChart(outDir, showLegend)
		html, err := injectFullHeightCSS(chart.Render)
		if err != nil {
			http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(html)
	}
}

// generateTreemapChart creates a treemap chart showing audit record types by count
func generateTreemapChart(outDir string, showLegend bool) *charts.TreeMap {
	stats := getAuditRecordStats(outDir)

	// Build treemap data organized by layer
	layerMap := getLayerMap()
	layerNodes := make(map[string]*opts.TreeMapNode)

	// Initialize layer nodes
	for _, layer := range []string{"Link Layer", "Network Layer", "Transport Layer", "Application Layer", "Stream Decoders", "Abstract Decoders"} {
		layerNodes[layer] = &opts.TreeMapNode{
			Name:     layer,
			Children: []opts.TreeMapNode{},
		}
	}

	// Add protocols to their layers
	for protocol, pstats := range stats {
		layer := layerMap[protocol]
		if layer == "" {
			layer = "Abstract Decoders"
		}

		if node, ok := layerNodes[layer]; ok {
			node.Children = append(node.Children, opts.TreeMapNode{
				Name:  protocol,
				Value: int(pstats.Count),
			})
		}
	}

	// Build final tree structure
	treeData := []opts.TreeMapNode{}
	for _, layer := range []string{"Link Layer", "Network Layer", "Transport Layer", "Application Layer", "Stream Decoders", "Abstract Decoders"} {
		if node, ok := layerNodes[layer]; ok && len(node.Children) > 0 {
			treeData = append(treeData, *node)
		}
	}

	graph := charts.NewTreeMap()
	graph.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Theme:           types.ThemeMacarons,
			Width:           "100%",
			Height:          "100%",
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Audit Record Types Distribution",
			Subtitle: "Grouped by protocol layer",
			Left:     "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
			SubtitleStyle: &opts.TextStyle{
				Color: "#cccccc",
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:      opts.Bool(true),
			Trigger:   "item",
			Formatter: "{b}: {c} records",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show: opts.Bool(showLegend),
		}),
	)

	graph.AddSeries("Audit Records", treeData).
		SetSeriesOptions(
			charts.WithTreeMapOpts(opts.TreeMapChart{
				Animation:  opts.Bool(true),
				Roam:       opts.Bool(true),
				UpperLabel: &opts.UpperLabel{Show: opts.Bool(true)},
				Levels: &[]opts.TreeMapLevel{
					{
						ItemStyle: &opts.ItemStyle{
							BorderColor: "#777",
							BorderWidth: 1,
							GapWidth:    1,
						},
						UpperLabel: &opts.UpperLabel{Show: opts.Bool(true)},
					},
					{
						ItemStyle: &opts.ItemStyle{
							BorderColor: "#666",
							BorderWidth: 2,
							GapWidth:    1,
						},
					},
					{
						ColorSaturation: []float32{0.35, 0.5},
						ItemStyle: &opts.ItemStyle{
							GapWidth:              1,
							BorderWidth:           0,
							BorderColorSaturation: 0.6,
						},
					},
				},
			}),
			charts.WithLabelOpts(opts.Label{
				Show:     opts.Bool(true),
				Position: "inside",
				Color:    "#ffffff",
				FontSize: 12,
			}),
		)

	return graph
}

// generateBar3DChart creates a 3D bar chart showing audit record types by count
func generateBar3DChart(outDir string) *charts.Bar3D {
	stats := getAuditRecordStats(outDir)
	layerMap := getLayerMap()

	// Organize by layer
	layers := []string{"Link Layer", "Network Layer", "Transport Layer", "Application Layer"}
	layerProtocols := make(map[string][]string)

	for protocol := range stats {
		layer := layerMap[protocol]
		if layer == "" {
			continue
		}
		layerProtocols[layer] = append(layerProtocols[layer], protocol)
	}

	// Build 3D data
	data := make([]opts.Chart3DData, 0)
	protocols := []string{}

	for layerIdx, layer := range layers {
		protos := layerProtocols[layer]
		for protoIdx, protocol := range protos {
			if pstats, ok := stats[protocol]; ok {
				data = append(data, opts.Chart3DData{
					Value: []interface{}{layerIdx, protoIdx, pstats.Count},
				})
				if layerIdx == 0 {
					protocols = append(protocols, protocol)
				}
			}
		}
	}

	bar3d := charts.NewBar3D()
	bar3d.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:           "100%",
			Height:          "100%",
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title: "Audit Record Types by Layer (3D)",
			Left:  "center",
			Top:   "5px",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithVisualMapOpts(opts.VisualMap{
			Calculable: opts.Bool(true),
			Max:        100000,
			InRange: &opts.VisualMapInRange{
				Color: []string{"#313695", "#4575b4", "#74add1", "#abd9e9", "#e0f3f8", "#fee090", "#fdae61", "#f46d43", "#d73027", "#a50026"},
			},
			Orient: "vertical",
			Right:  "0",
			Bottom: "0",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithGrid3DOpts(opts.Grid3D{
			BoxWidth:    200,
			BoxDepth:    80,
			ViewControl: &opts.ViewControl{AutoRotate: opts.Bool(true), AutoRotateSpeed: 10},
		}),
		charts.WithXAxis3DOpts(opts.XAxis3D{Data: layers}),
		charts.WithYAxis3DOpts(opts.YAxis3D{Data: protocols}),
		charts.WithZAxis3DOpts(opts.ZAxis3D{Name: "Record Count"}),
	)

	bar3d.AddSeries("audit records", data, charts.WithBar3DChartOpts(opts.Bar3DChart{Shading: "lambert"}))
	return bar3d
}

// generateGraphChart creates a graph chart showing audit record types as nodes
func generateGraphChart(outDir string, showLegend bool) *charts.Graph {
	stats := getAuditRecordStats(outDir)
	layerMap := getLayerMap()

	// Create nodes for each audit record type
	nodes := make([]opts.GraphNode, 0)
	categories := []string{"Link Layer", "Network Layer", "Transport Layer", "Application Layer", "Other"}

	for protocol, pstats := range stats {
		layer := layerMap[protocol]
		if layer == "" {
			layer = "Other"
		}

		// Determine category index
		categoryIdx := 4 // default to "Other"
		for i, cat := range categories {
			if cat == layer {
				categoryIdx = i
				break
			}
		}

		// Node size based on record count (logarithmic scale for better visualization)
		size := float32(10)
		if pstats.Count > 0 {
			size = float32(10 + (pstats.Count / 1000))
			if size > 100 {
				size = 100
			}
		}

		nodes = append(nodes, opts.GraphNode{
			Name:       protocol,
			Value:      float32(pstats.Count),
			SymbolSize: size,
			Category:   categoryIdx,
		})
	}

	// Create links based on protocol hierarchy
	links := make([]opts.GraphLink, 0)
	// Link protocols in adjacent layers
	linkLayerProtos := []string{}
	networkLayerProtos := []string{}
	transportLayerProtos := []string{}
	appLayerProtos := []string{}

	for protocol := range stats {
		layer := layerMap[protocol]
		switch layer {
		case "Link Layer":
			linkLayerProtos = append(linkLayerProtos, protocol)
		case "Network Layer":
			networkLayerProtos = append(networkLayerProtos, protocol)
		case "Transport Layer":
			transportLayerProtos = append(transportLayerProtos, protocol)
		case "Application Layer":
			appLayerProtos = append(appLayerProtos, protocol)
		}
	}

	// Link Link Layer -> Network Layer
	for _, link := range linkLayerProtos {
		for _, network := range networkLayerProtos {
			links = append(links, opts.GraphLink{
				Source: link,
				Target: network,
			})
		}
	}

	// Link Network Layer -> Transport Layer
	for _, network := range networkLayerProtos {
		for _, transport := range transportLayerProtos {
			links = append(links, opts.GraphLink{
				Source: network,
				Target: transport,
			})
		}
	}

	// Link Transport Layer -> Application Layer
	for _, transport := range transportLayerProtos {
		for _, app := range appLayerProtos {
			links = append(links, opts.GraphLink{
				Source: transport,
				Target: app,
			})
		}
	}

	graph := charts.NewGraph()
	graph.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:           "100%",
			Height:          "100%",
			Theme:           types.ThemeMacarons,
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title: "Protocol Relationship Graph",
			Left:  "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Show:    opts.Bool(true),
			Trigger: "item",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Data:   categories,
			Bottom: "0",
			Left:   "center",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	// Add categories
	graphCategories := make([]*opts.GraphCategory, 0)
	for _, cat := range categories {
		graphCategories = append(graphCategories, &opts.GraphCategory{Name: cat})
	}

	graph.AddSeries("protocols", nodes, links,
		charts.WithGraphChartOpts(opts.GraphChart{
			Force:      &opts.GraphForce{Repulsion: 1000, Gravity: 0.1, EdgeLength: 150},
			Layout:     "force",
			Roam:       opts.Bool(true),
			Categories: graphCategories,
		}),
		charts.WithLabelOpts(opts.Label{
			Show:     opts.Bool(true),
			Position: "right",
			Color:    "#ffffff",
		}),
	)

	return graph
}

// getAuditRecordStats reads audit files and returns record counts
func getAuditRecordStats(outDir string) map[string]ProtocolStats {
	stats := make(map[string]ProtocolStats)

	files, err := os.ReadDir(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read output directory: %v", err)
		return stats
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".ncap.gz") {
			continue
		}

		fileName := strings.TrimSuffix(file.Name(), ".ncap.gz")
		parts := strings.Split(fileName, ".")
		if len(parts) < 1 {
			continue
		}

		protocol := parts[0]
		fullPath := filepath.Join(outDir, file.Name())
		fileInfo, err := os.Stat(fullPath)
		if err != nil {
			continue
		}

		count := int64(0)
		bytes := fileInfo.Size()

		// Try to read metadata
		metaPath := fullPath + ".meta.json"
		if metaData, err := os.ReadFile(metaPath); err == nil {
			var meta struct {
				RecordCount int64 `json:"recordCount"`
			}
			if err := json.Unmarshal(metaData, &meta); err == nil && meta.RecordCount > 0 {
				count = meta.RecordCount
			}
		}

		if count == 0 {
			count = bytes / 100
		}

		layer := getLayerMap()[protocol]
		if layer == "" {
			layer = "Custom Abstraction"
		}

		stats[protocol] = ProtocolStats{
			Count: count,
			Bytes: bytes,
			Layer: layer,
		}
	}

	return stats
}

// getLayerMap returns the layer mapping for protocols
func getLayerMap() map[string]string {
	return map[string]string{
		// Link Layer
		"Ethernet":           "Link Layer",
		"Dot1Q":              "Link Layer",
		"Dot11":              "Link Layer",
		"LLC":                "Link Layer",
		"SNAP":               "Link Layer",
		"ARP":                "Link Layer",
		"CiscoDiscovery":     "Link Layer",
		"NortelDiscovery":    "Link Layer",
		"LinkLayerDiscovery": "Link Layer",
		"STP":                "Link Layer",
		"LLDP":               "Link Layer",
		// Network Layer
		"IPv4":     "Network Layer",
		"IPv6":     "Network Layer",
		"ICMPv4":   "Network Layer",
		"ICMPv6":   "Network Layer",
		"IGMP":     "Network Layer",
		"IPSecAH":  "Network Layer",
		"IPSecESP": "Network Layer",
		"GRE":      "Network Layer",
		"MPLS":     "Network Layer",
		// Transport Layer
		"TCP":  "Transport Layer",
		"UDP":  "Transport Layer",
		"SCTP": "Transport Layer",
		// Application Layer
		"HTTP":           "Application Layer",
		"TLS":            "Application Layer",
		"TLSClientHello": "Application Layer",
		"TLSServerHello": "Application Layer",
		"DNS":            "Application Layer",
		"SMTP":           "Application Layer",
		"POP3":           "Application Layer",
		"SSH":            "Application Layer",
		"FTP":            "Application Layer",
		"Telnet":         "Application Layer",
		"SIP":            "Application Layer",
		"NTP":            "Application Layer",
		"DHCPv4":         "Application Layer",
		"DHCPv6":         "Application Layer",
		"DHCP":           "Application Layer",
		"Modbus":         "Application Layer",
		"ENIP":           "Application Layer",
		"CIP":            "Application Layer",
		"Diameter":       "Application Layer",
		"VXLAN":          "Application Layer",
		"Geneve":         "Application Layer",
	}
}
