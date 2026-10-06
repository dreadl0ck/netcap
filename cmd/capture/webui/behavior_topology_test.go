package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dreadl0ck/netcap/internal/behavior"
)

func TestInventoryAPIAndSandboxedTopologyData(t *testing.T) {
	s := behaviorServerFixture(t)
	read := httptest.NewRecorder()
	s.handleBehavior(read, httptest.NewRequest(http.MethodGet, "/api/behavior", nil))
	var state behavior.Snapshot
	if err := json.Unmarshal(read.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	var id string
	for key := range state.Observed {
		id = key
		break
	}
	label := `</script><img src=x onerror=alert(1)>`
	body, _ := json.Marshal(map[string]any{"action": "inventory", "version": state.Version, "reason": "label fixture", "inventory": map[string]string{"id": id, "name": label}})
	response := httptest.NewRecorder()
	s.handleBehaviorChange(response, httptest.NewRequest(http.MethodPost, "/api/behavior/change", strings.NewReader(string(body))))
	if response.Code != http.StatusOK {
		t.Fatalf("inventory = %d: %s", response.Code, response.Body)
	}
	graph := httptest.NewRecorder()
	s.handleBehaviorTopology(graph, httptest.NewRequest(http.MethodGet, "/api/behavior/topology?format=html", nil))
	if graph.Code != http.StatusOK {
		t.Fatalf("graph = %d: %s", graph.Code, graph.Body)
	}
	if strings.Contains(graph.Body.String(), label) || strings.Contains(graph.Body.String(), "<img src=x") {
		t.Fatal("inventory label escaped chart script containment")
	}
	data := httptest.NewRecorder()
	s.handleBehaviorTopology(data, httptest.NewRequest(http.MethodGet, "/api/behavior/topology?maxNodes=1", nil))
	var topology behavior.Topology
	if err := json.Unmarshal(data.Body.Bytes(), &topology); err != nil {
		t.Fatal(err)
	}
	if len(topology.Nodes) != 1 || topology.Nodes[0].Name != label {
		t.Fatal("JSON topology lost inventory label")
	}
}
