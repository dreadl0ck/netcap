package webui

import (
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
)

func (s *Server) handleBehaviorTopology(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	var snapshot behavior.Snapshot
	if engine := s.activeBehavior(dir); engine != nil {
		snapshot = engine.Snapshot()
	} else {
		var err error
		snapshot, err = behavior.ReadSnapshot(filepath.Join(dir, "Behavior.json"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("maxNodes"))
	topology := behavior.BuildTopology(snapshot, limit, r.URL.Query().Get("scope"))
	if r.URL.Query().Get("format") != "html" {
		RespondJSON(w, http.StatusOK, topology)
		return
	}
	graph := charts.NewGraph()
	graph.SetGlobalOptions(charts.WithInitializationOpts(getDefaultChartInit()), charts.WithTitleOpts(opts.Title{Title: "Observed network topology", Left: "center", TitleStyle: &opts.TextStyle{Color: "#ffffff"}}), charts.WithTooltipOpts(opts.Tooltip{Show: opts.Bool(false)}))
	nodes := make([]opts.GraphNode, 0, len(topology.Nodes))
	index := make(map[string]int, len(topology.Nodes))
	for i, node := range topology.Nodes {
		index[node.ID] = i
		color, symbol := "#38bdf8", "circle"
		if node.Kind == "device" {
			color, symbol = "#00ff88", "roundRect"
		}
		if node.Kind == "subnet" {
			color, symbol = "#fbbf24", "diamond"
		}
		name := node.Name + "\n" + node.Scope.Sensor + "/" + node.Scope.Interface
		for _, vlan := range node.Scope.VLANs {
			name += "/VLAN" + strconv.Itoa(int(vlan))
		}
		nodes = append(nodes, opts.GraphNode{Name: name, Symbol: symbol, SymbolSize: 24, ItemStyle: &opts.ItemStyle{Color: color}})
	}
	links := make([]opts.GraphLink, 0, len(topology.Links))
	for _, link := range topology.Links {
		links = append(links, opts.GraphLink{Source: index[link.Source], Target: index[link.Target]})
	}
	graph.AddSeries("observed", nodes, links, charts.WithGraphChartOpts(opts.GraphChart{Layout: "force", Roam: opts.Bool(true), Force: &opts.GraphForce{Repulsion: 500, EdgeLength: 100}}), charts.WithLabelOpts(opts.Label{Show: opts.Bool(true), Color: "#ffffff"}))
	html, err := injectFullHeightCSS(graph.Render)
	if err != nil {
		http.Error(w, "topology render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write(html)
}
