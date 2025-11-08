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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	echartstypes "github.com/go-echarts/go-echarts/v2/types"

	"github.com/dreadl0ck/netcap/types"
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

	chart := generateBar3DChart(outDir, showLegend)
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

		// Parse showLegend parameter (default to false)
		showLegendStr := r.URL.Query().Get("showLegend")
		showLegend := showLegendStr == "true"

		chart := generateBar3DChart(outDir, showLegend)
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

// handleVisualizeGeo returns HTML for geo chart showing IP geolocation distribution
func (s *Server) handleVisualizeGeo(w http.ResponseWriter, r *http.Request) {
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

	chart := generateGeoChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeGeo is an exported handler factory for service mode
func HandleVisualizeGeo(outDir string) http.HandlerFunc {
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

		chart := generateGeoChart(outDir, showLegend)
		html, err := injectFullHeightCSS(chart.Render)
		if err != nil {
			http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(html)
	}
}

// handleVisualizeScatter3D returns HTML for 3D scatter chart showing connection patterns
func (s *Server) handleVisualizeScatter3D(w http.ResponseWriter, r *http.Request) {
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

	chart := generateScatter3DChart(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeScatter3D is an exported handler factory for service mode
func HandleVisualizeScatter3D(outDir string) http.HandlerFunc {
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

		chart := generateScatter3DChart(outDir, showLegend)
		html, err := injectFullHeightCSS(chart.Render)
		if err != nil {
			http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(html)
	}
}

// handleVisualizeHostsGraph returns HTML for network graph showing IP communication patterns
func (s *Server) handleVisualizeHostsGraph(w http.ResponseWriter, r *http.Request) {
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

	chart := generateHostsGraph(outDir, showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeHostsGraph is an exported handler factory for service mode
func HandleVisualizeHostsGraph(outDir string) http.HandlerFunc {
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

		chart := generateHostsGraph(outDir, showLegend)
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
			Theme:           echartstypes.ThemeMacarons,
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
func generateBar3DChart(outDir string, showLegend bool) *charts.Bar3D {
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
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Right:  "10",
			Top:    "10",
			Orient: "vertical",
			TextStyle: &opts.TextStyle{
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
			Right:  "10",
			Bottom: "10",
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

	bar3d.AddSeries("Audit Records", data, charts.WithBar3DChartOpts(opts.Bar3DChart{Shading: "lambert"}))
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
			Theme:           echartstypes.ThemeMacarons,
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

// generateGeoChart creates a geo chart showing IP geolocation distribution from IPProfile data
func generateGeoChart(outDir string, showLegend bool) *charts.Geo {
	geoData := getIPProfileGeolocations(outDir)

	geo := charts.NewGeo()
	geo.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:           "100%",
			Height:          "100%",
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "IP Geolocation Distribution",
			Subtitle: "Based on IPProfile data",
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
			Formatter: "{b}: {c} IPs",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Orient: "vertical",
			Left:   "left",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithGeoComponentOpts(opts.GeoComponent{
			Map: "world",
			ItemStyle: &opts.ItemStyle{
				Color:       "#404040",
				BorderColor: "#666666",
			},
		}),
		charts.WithVisualMapOpts(opts.VisualMap{
			Calculable: opts.Bool(true),
			InRange: &opts.VisualMapInRange{
				Color: []string{"#50a3ba", "#eac736", "#d94e5d"},
			},
			Min:    0,
			Max:    float32(getMaxGeoCount(geoData)),
			Orient: "vertical",
			Right:  "10",
			Bottom: "10",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	// Add scatter points for IPs
	geo.AddSeries("IP Locations", echartstypes.ChartEffectScatter, geoData,
		charts.WithRippleEffectOpts(opts.RippleEffect{
			Period:    4,
			Scale:     6,
			BrushType: "stroke",
		}),
		charts.WithLabelOpts(opts.Label{
			Show:     opts.Bool(false),
			Position: "right",
			Color:    "#ffffff",
		}),
	)

	return geo
}

// getIPProfileGeolocations reads IPProfile data and extracts geolocation information
func getIPProfileGeolocations(outDir string) []opts.GeoData {
	geoMap := make(map[string]int) // country/city -> count
	locationCoords := getLocationCoordinates()

	filePath := filepath.Join(outDir, "IPProfile.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] IPProfile file not found: %s", filePath)
		return []opts.GeoData{}
	}

	// Read IPProfile records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open IPProfile file: %v", err)
		return []opts.GeoData{}
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read IPProfile header: %v", err)
		return []opts.GeoData{}
	}

	// Read records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading IPProfile record: %v", err)
			continue
		}

		// Type assert to IPProfile
		ipProfile, ok := record.(*types.IPProfile)
		if !ok {
			continue
		}

		// Extract geolocation
		geoloc := ipProfile.GetGeolocation()
		if geoloc != "" {
			// Parse geolocation string (format: "US (New York)" or just "US")
			location := parseGeolocation(geoloc)
			if location != "" {
				geoMap[location]++
			}
		}
	}

	// Convert to GeoData slice
	geoData := make([]opts.GeoData, 0, len(geoMap))
	for location, count := range geoMap {
		if coords, ok := locationCoords[location]; ok {
			geoData = append(geoData, opts.GeoData{
				Name:  location,
				Value: []float64{coords[0], coords[1], float64(count)},
			})
		}
	}

	return geoData
}

// parseGeolocation extracts country code from geolocation string
func parseGeolocation(geoloc string) string {
	// Format can be "US (New York)" or just "US"
	// For now, we'll use the country code as the key
	if len(geoloc) >= 2 {
		// Extract country code (first 2 characters)
		return geoloc[:2]
	}
	return ""
}

// getMaxGeoCount returns the maximum count from geo data
func getMaxGeoCount(geoData []opts.GeoData) int {
	max := 0
	for _, data := range geoData {
		if values, ok := data.Value.([]float64); ok && len(values) >= 3 {
			count := int(values[2])
			if count > max {
				max = count
			}
		}
	}
	if max == 0 {
		max = 100 // default max
	}
	return max
}

// handleVisualizeGeoAll returns HTML for geo chart showing IP geolocation distribution across all captures
func (s *Server) handleVisualizeGeoAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse showLegend parameter (default to false)
	showLegendStr := r.URL.Query().Get("showLegend")
	showLegend := showLegendStr == "true"

	chart := s.generateGeoChartAll(showLegend)
	html, err := injectFullHeightCSS(chart.Render)
	if err != nil {
		http.Error(w, "Failed to generate chart", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(html)
}

// HandleVisualizeGeoAll is an exported handler factory for service mode
func HandleVisualizeGeoAll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// This simplified version won't work - need server reference
		http.Error(w, "Not implemented in standalone mode", http.StatusNotImplemented)
	}
}

// generateGeoChartAll creates a geo chart showing IP geolocation distribution from all captures
func (s *Server) generateGeoChartAll(showLegend bool) *charts.Geo {
	geoData := s.getAllCapturesGeolocations()

	geo := charts.NewGeo()
	geo.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:           "100%",
			Height:          "100%",
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Global IP Geolocation Distribution",
			Subtitle: "Aggregated data across all captures",
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
			Formatter: "{b}: {c} IPs",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Orient: "vertical",
			Left:   "left",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithGeoComponentOpts(opts.GeoComponent{
			Map: "world",
			ItemStyle: &opts.ItemStyle{
				Color:       "#404040",
				BorderColor: "#666666",
			},
		}),
		charts.WithVisualMapOpts(opts.VisualMap{
			Calculable: opts.Bool(true),
			InRange: &opts.VisualMapInRange{
				Color: []string{"#50a3ba", "#eac736", "#d94e5d"},
			},
			Min:    0,
			Max:    float32(getMaxGeoCount(geoData)),
			Orient: "vertical",
			Right:  "10",
			Bottom: "10",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	// Add scatter points for IPs
	geo.AddSeries("IP Locations", echartstypes.ChartEffectScatter, geoData,
		charts.WithRippleEffectOpts(opts.RippleEffect{
			Period:    4,
			Scale:     6,
			BrushType: "stroke",
		}),
		charts.WithLabelOpts(opts.Label{
			Show:     opts.Bool(false),
			Position: "right",
			Color:    "#ffffff",
		}),
	)

	return geo
}

// getAllCapturesGeolocations aggregates geolocation data from all captures
func (s *Server) getAllCapturesGeolocations() []opts.GeoData {
	geoMap := make(map[string]int) // country code -> count
	locationCoords := getLocationCoordinates()

	s.mu.RLock()
	isServiceMode := s.isServiceMode
	outDir := s.outDir
	sessionManager := s.sessionManager
	s.mu.RUnlock()

	// Collect all output directories to scan
	var outputDirs []string

	if isServiceMode && sessionManager != nil {
		// In service mode, get all sessions
		allSessions := sessionManager.GetAllSessions()
		for _, session := range allSessions {
			// Only include completed sessions with output directories
			if session.Status == StatusCompleted && session.OutputDir != "" {
				outputDirs = append(outputDirs, session.OutputDir)
			}
		}
	} else {
		// In local mode, just use the current output directory
		if outDir != "" {
			outputDirs = append(outputDirs, outDir)
		}
	}

	// If no output directories found, return empty data
	if len(outputDirs) == 0 {
		log.Printf("[WebUI] No output directories found for geolocation aggregation")
		return []opts.GeoData{}
	}

	// Iterate through all output directories and aggregate geolocation data
	for _, dir := range outputDirs {
		filePath := filepath.Join(dir, "IPProfile.ncap.gz")

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			continue
		}

		// Read IPProfile records
		reader, err := NewAuditRecordReader(filePath)
		if err != nil {
			log.Printf("[WebUI] Failed to open IPProfile file %s: %v", filePath, err)
			continue
		}

		// Read header
		_, err = reader.ReadHeader()
		if err != nil {
			log.Printf("[WebUI] Failed to read IPProfile header from %s: %v", filePath, err)
			reader.Close()
			continue
		}

		// Read records
		for {
			record, err := reader.NextRecord()
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Printf("[WebUI] Error reading IPProfile record from %s: %v", filePath, err)
				continue
			}

			// Type assert to IPProfile
			ipProfile, ok := record.(*types.IPProfile)
			if !ok {
				continue
			}

			// Extract geolocation
			geoloc := ipProfile.GetGeolocation()
			if geoloc != "" {
				// Parse geolocation string (format: "US (New York)" or just "US")
				location := parseGeolocation(geoloc)
				if location != "" {
					geoMap[location]++
				}
			}
		}

		reader.Close()
	}

	// Convert to GeoData slice
	geoData := make([]opts.GeoData, 0, len(geoMap))
	for location, count := range geoMap {
		if coords, ok := locationCoords[location]; ok {
			geoData = append(geoData, opts.GeoData{
				Name:  location,
				Value: []float64{coords[0], coords[1], float64(count)},
			})
		}
	}

	log.Printf("[WebUI] Aggregated geolocation data from %d directories: %d unique locations", len(outputDirs), len(geoData))
	return geoData
}

// getLocationCoordinates returns a map of country codes to [longitude, latitude] coordinates
func getLocationCoordinates() map[string][]float64 {
	return map[string][]float64{
		// Major countries with their approximate center coordinates [longitude, latitude]
		"US": {-95.71, 37.09},  // United States
		"CN": {104.19, 35.86},  // China
		"JP": {138.25, 36.20},  // Japan
		"DE": {10.45, 51.16},   // Germany
		"GB": {-3.44, 55.38},   // United Kingdom
		"FR": {2.21, 46.23},    // France
		"CA": {-106.35, 56.13}, // Canada
		"AU": {133.77, -25.27}, // Australia
		"BR": {-51.93, -14.24}, // Brazil
		"IN": {78.96, 20.59},   // India
		"RU": {105.32, 61.52},  // Russia
		"IT": {12.57, 41.87},   // Italy
		"ES": {-3.75, 40.46},   // Spain
		"MX": {-102.55, 23.63}, // Mexico
		"KR": {127.77, 37.57},  // South Korea
		"NL": {5.29, 52.13},    // Netherlands
		"SE": {18.64, 60.13},   // Sweden
		"NO": {8.47, 60.47},    // Norway
		"FI": {25.75, 61.92},   // Finland
		"DK": {9.50, 56.26},    // Denmark
		"PL": {19.15, 51.92},   // Poland
		"BE": {4.47, 50.50},    // Belgium
		"CH": {8.23, 46.82},    // Switzerland
		"AT": {14.55, 47.52},   // Austria
		"IE": {-8.24, 53.41},   // Ireland
		"PT": {-8.22, 39.40},   // Portugal
		"GR": {21.82, 39.07},   // Greece
		"CZ": {15.47, 49.82},   // Czech Republic
		"RO": {24.97, 45.94},   // Romania
		"HU": {19.50, 47.16},   // Hungary
		"TR": {35.24, 38.96},   // Turkey
		"IL": {34.85, 31.05},   // Israel
		"SA": {45.08, 23.89},   // Saudi Arabia
		"AE": {53.85, 23.42},   // United Arab Emirates
		"ZA": {22.94, -30.56},  // South Africa
		"EG": {30.80, 26.82},   // Egypt
		"NG": {8.68, 9.08},     // Nigeria
		"KE": {37.91, -0.02},   // Kenya
		"AR": {-63.62, -38.42}, // Argentina
		"CL": {-71.54, -35.68}, // Chile
		"CO": {-74.30, 4.57},   // Colombia
		"PE": {-75.02, -9.19},  // Peru
		"VE": {-66.59, 6.42},   // Venezuela
		"TH": {100.99, 15.87},  // Thailand
		"VN": {108.28, 14.06},  // Vietnam
		"MY": {101.98, 4.21},   // Malaysia
		"SG": {103.82, 1.35},   // Singapore
		"ID": {113.92, -0.79},  // Indonesia
		"PH": {121.77, 12.88},  // Philippines
		"PK": {69.35, 30.38},   // Pakistan
		"BD": {90.36, 23.68},   // Bangladesh
		"NZ": {174.89, -40.90}, // New Zealand
		"UA": {31.17, 48.38},   // Ukraine
		"BY": {27.95, 53.71},   // Belarus
		"RS": {21.01, 44.02},   // Serbia
		"HR": {15.20, 45.10},   // Croatia
		"BG": {25.49, 42.73},   // Bulgaria
		"SK": {19.70, 48.67},   // Slovakia
		"SI": {14.99, 46.15},   // Slovenia
		"LT": {23.88, 55.17},   // Lithuania
		"LV": {24.60, 56.88},   // Latvia
		"EE": {25.01, 58.60},   // Estonia
		"IS": {-19.02, 64.96},  // Iceland
		"LU": {6.13, 49.82},    // Luxembourg
		"MT": {14.38, 35.94},   // Malta
		"CY": {33.43, 35.13},   // Cyprus
		"HK": {114.11, 22.40},  // Hong Kong
		"TW": {120.96, 23.70},  // Taiwan
		"MO": {113.54, 22.20},  // Macau
	}
}

// generateScatter3DChart creates a 3D scatter chart showing connection patterns
func generateScatter3DChart(outDir string, showLegend bool) *charts.Scatter3D {
	scatter3DData := getConnectionScatter3DData(outDir)

	scatter3d := charts.NewScatter3D()
	scatter3d.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:           "100%",
			Height:          "100%",
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Connection Pattern Analysis (3D)",
			Subtitle: "Packets vs Bytes vs Duration",
			Left:     "center",
			TitleStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
			SubtitleStyle: &opts.TextStyle{
				Color: "#cccccc",
			},
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   opts.Bool(showLegend),
			Orient: "vertical",
			Left:   "left",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithVisualMapOpts(opts.VisualMap{
			Calculable: opts.Bool(true),
			Max:        100,
			InRange: &opts.VisualMapInRange{
				Color: []string{"#313695", "#4575b4", "#74add1", "#abd9e9", "#e0f3f8", "#fee090", "#fdae61", "#f46d43", "#d73027", "#a50026"},
			},
			Orient: "vertical",
			Right:  "10",
			Bottom: "10",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
		charts.WithXAxis3DOpts(opts.XAxis3D{
			Name: "Packets",
			Type: "value",
		}),
		charts.WithYAxis3DOpts(opts.YAxis3D{
			Name: "Bytes (KB)",
			Type: "value",
		}),
		charts.WithZAxis3DOpts(opts.ZAxis3D{
			Name: "Duration (s)",
			Type: "value",
		}),
		charts.WithGrid3DOpts(opts.Grid3D{
			BoxWidth:    200,
			BoxDepth:    80,
			BoxHeight:   80,
			ViewControl: &opts.ViewControl{AutoRotate: opts.Bool(true), AutoRotateSpeed: 10},
		}),
	)

	scatter3d.AddSeries("Connections", scatter3DData)
	return scatter3d
}

// getConnectionScatter3DData reads connection data and extracts 3D scatter data
func getConnectionScatter3DData(outDir string) []opts.Chart3DData {
	filePath := filepath.Join(outDir, "Connection.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] Connection file not found: %s", filePath)
		return []opts.Chart3DData{}
	}

	// Read Connection records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open Connection file: %v", err)
		return []opts.Chart3DData{}
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read Connection header: %v", err)
		return []opts.Chart3DData{}
	}

	data := make([]opts.Chart3DData, 0)
	maxRecords := 1000 // Limit to 1000 points for performance

	// Read records
	for i := 0; i < maxRecords; i++ {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading Connection record: %v", err)
			continue
		}

		// Type assert to Connection
		conn, ok := record.(*types.Connection)
		if !ok {
			continue
		}

		// Calculate duration in seconds
		duration := float64(0)
		if conn.TimestampFirst > 0 && conn.TimestampLast > 0 {
			duration = float64(conn.TimestampLast-conn.TimestampFirst) / 1e9
		}

		// Convert bytes to KB for better visualization
		bytesKB := float64(conn.TotalSize) / 1024

		// Normalize values for better visualization
		packets := normalizeValue(float64(conn.NumPackets), 0, 10000, 0, 100)
		bytes := normalizeValue(bytesKB, 0, 10000, 0, 100)
		dur := normalizeValue(duration, 0, 300, 0, 100) // Cap at 5 minutes

		data = append(data, opts.Chart3DData{
			Name: conn.SrcIP + " -> " + conn.DstIP,
			Value: []interface{}{
				int(packets),
				int(bytes),
				int(dur),
			},
		})
	}

	// If no connection data, try IPProfile
	if len(data) == 0 {
		return getIPProfileScatter3DData(outDir)
	}

	return data
}

// getIPProfileScatter3DData reads IPProfile data as fallback for 3D scatter
func getIPProfileScatter3DData(outDir string) []opts.Chart3DData {
	filePath := filepath.Join(outDir, "IPProfile.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] IPProfile file not found: %s", filePath)
		return []opts.Chart3DData{}
	}

	// Read IPProfile records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open IPProfile file: %v", err)
		return []opts.Chart3DData{}
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read IPProfile header: %v", err)
		return []opts.Chart3DData{}
	}

	data := make([]opts.Chart3DData, 0)
	maxRecords := 500 // Limit to 500 points for performance

	// Read records
	for i := 0; i < maxRecords; i++ {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading IPProfile record: %v", err)
			continue
		}

		// Type assert to IPProfile
		ipProfile, ok := record.(*types.IPProfile)
		if !ok {
			continue
		}

		// Convert bytes to KB
		bytesKB := float64(ipProfile.Bytes) / 1024

		// Count unique ports (as a metric of activity diversity)
		uniquePorts := len(ipProfile.SrcPorts) + len(ipProfile.DstPorts)

		// Normalize values for better visualization
		packets := normalizeValue(float64(ipProfile.NumPackets), 0, 10000, 0, 100)
		bytes := normalizeValue(bytesKB, 0, 10000, 0, 100)
		ports := normalizeValue(float64(uniquePorts), 0, 100, 0, 100)

		data = append(data, opts.Chart3DData{
			Name: ipProfile.Addr,
			Value: []interface{}{
				int(packets),
				int(bytes),
				int(ports),
			},
		})
	}

	return data
}

// normalizeValue normalizes a value from one range to another
func normalizeValue(value, oldMin, oldMax, newMin, newMax float64) float64 {
	if oldMax == oldMin {
		return newMin
	}
	normalized := ((value-oldMin)/(oldMax-oldMin))*(newMax-newMin) + newMin

	// Clamp to new range
	if normalized < newMin {
		normalized = newMin
	}
	if normalized > newMax {
		normalized = newMax
	}

	return normalized
}

// generateHostsGraph creates a network graph showing IP communication patterns
func generateHostsGraph(outDir string, showLegend bool) *charts.Graph {
	nodes, links := getHostsCommunicationData(outDir)

	graph := charts.NewGraph()

	// Define categories for internal vs external IPs
	categories := []*opts.GraphCategory{
		{Name: "Internal Network"},
		{Name: "External Network"},
		{Name: "High Traffic Internal"},
		{Name: "High Traffic External"},
	}

	graph.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			Width:           "100%",
			Height:          "100%",
			BackgroundColor: "#1e1e1e",
		}),
		charts.WithTitleOpts(opts.Title{
			Title:    "Host Communication Graph",
			Subtitle: "Network connections between IP addresses (Internal vs External)",
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
			Show:   opts.Bool(true),
			Data:   []string{"Internal Network", "External Network", "High Traffic Internal", "High Traffic External"},
			Bottom: "0",
			Left:   "center",
			TextStyle: &opts.TextStyle{
				Color: "#ffffff",
			},
		}),
	)

	graph.AddSeries("hosts", nodes, links,
		charts.WithGraphChartOpts(opts.GraphChart{
			Force: &opts.GraphForce{
				Repulsion:  3000,
				Gravity:    0.1,
				EdgeLength: 150,
			},
			Layout:             "force",
			Roam:               opts.Bool(true),
			FocusNodeAdjacency: opts.Bool(true),
			Categories:         categories,
		}),
		charts.WithLabelOpts(opts.Label{
			Show:     opts.Bool(true),
			Position: "right",
			Color:    "#ffffff",
			FontSize: 10,
		}),
		charts.WithLineStyleOpts(opts.LineStyle{
			Curveness: 0.3,
			Width:     1,
		}),
	)

	return graph
}

// getHostsCommunicationData reads connection data and builds a communication graph
func getHostsCommunicationData(outDir string) ([]opts.GraphNode, []opts.GraphLink) {
	filePath := filepath.Join(outDir, "Connection.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] Connection file not found: %s", filePath)
		return []opts.GraphNode{}, []opts.GraphLink{}
	}

	// Read Connection records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		log.Printf("[WebUI] Failed to open Connection file: %v", err)
		return []opts.GraphNode{}, []opts.GraphLink{}
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		log.Printf("[WebUI] Failed to read Connection header: %v", err)
		return []opts.GraphNode{}, []opts.GraphLink{}
	}

	// Track unique IPs and their connections
	ipStats := make(map[string]*ipNodeStats)
	connectionPairs := make(map[string]int) // "srcIP->dstIP" -> count

	maxRecords := 5000 // Limit for performance

	// Read records
	for i := 0; i < maxRecords; i++ {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading Connection record: %v", err)
			continue
		}

		// Type assert to Connection
		conn, ok := record.(*types.Connection)
		if !ok {
			continue
		}

		srcIP := conn.SrcIP
		dstIP := conn.DstIP

		if srcIP == "" || dstIP == "" {
			continue
		}

		// Track IP statistics
		if _, exists := ipStats[srcIP]; !exists {
			ipStats[srcIP] = &ipNodeStats{
				packetsOut: 0,
				packetsIn:  0,
				bytesOut:   0,
				bytesIn:    0,
			}
		}
		if _, exists := ipStats[dstIP]; !exists {
			ipStats[dstIP] = &ipNodeStats{
				packetsOut: 0,
				packetsIn:  0,
				bytesOut:   0,
				bytesIn:    0,
			}
		}

		// Update stats
		ipStats[srcIP].packetsOut += int64(conn.NumPackets)
		ipStats[srcIP].bytesOut += uint64(conn.TotalSize)
		ipStats[dstIP].packetsIn += int64(conn.NumPackets)
		ipStats[dstIP].bytesIn += uint64(conn.TotalSize)

		// Track connection pairs
		pairKey := srcIP + "->" + dstIP
		connectionPairs[pairKey]++
	}

	// Build nodes
	nodes := make([]opts.GraphNode, 0, len(ipStats))
	for ip, stats := range ipStats {
		// Calculate node size based on total traffic
		totalPackets := stats.packetsIn + stats.packetsOut
		nodeSize := float32(20 + (totalPackets / 100))
		if nodeSize > 100 {
			nodeSize = 100
		}
		if nodeSize < 15 {
			nodeSize = 15
		}

		// Determine category based on internal/external and traffic volume
		isInternal := isPrivateIP(ip)
		isHighTraffic := totalPackets > 1000 // Consider high traffic threshold

		category := 0
		if isInternal {
			if isHighTraffic {
				category = 2 // High Traffic Internal
			} else {
				category = 0 // Internal Network
			}
		} else {
			if isHighTraffic {
				category = 3 // High Traffic External
			} else {
				category = 1 // External Network
			}
		}

		nodes = append(nodes, opts.GraphNode{
			Name:       ip,
			SymbolSize: nodeSize,
			Category:   category,
			Value:      float32(totalPackets),
		})
	}

	// Build links
	links := make([]opts.GraphLink, 0, len(connectionPairs))
	for pair, count := range connectionPairs {
		// Parse pair
		parts := strings.Split(pair, "->")
		if len(parts) != 2 {
			continue
		}

		// Link width based on connection count
		linkValue := float32(count)

		links = append(links, opts.GraphLink{
			Source: parts[0],
			Target: parts[1],
			Value:  linkValue,
		})
	}

	return nodes, links
}

// ipNodeStats tracks statistics for a single IP node
type ipNodeStats struct {
	packetsOut int64
	packetsIn  int64
	bytesOut   uint64
	bytesIn    uint64
}

// isPrivateIP checks if an IP address is in a private/internal network range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for IPv4 private ranges
	if ip.To4() != nil {
		// 10.0.0.0/8
		if ip[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip[0] == 192 && ip[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip[0] == 169 && ip[1] == 254 {
			return true
		}
	} else {
		// Check for IPv6 private ranges
		// fc00::/7 (Unique Local Address)
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
		// fe80::/10 (Link-Local)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		// ::1/128 (loopback)
		if ip.IsLoopback() {
			return true
		}
	}

	return false
}
