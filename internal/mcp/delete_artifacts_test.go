package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestDeleteSessionInvalidatesOnlyItsArtifacts(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"success":true,"session_id":"owned","input_file":"/owned.pcap"}`)
	}))
	defer backend.Close()
	s, err := New(Options{BaseURL: backend.URL, CarveDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	owned, _, _ := s.carve.Put("owned", "owned", "fixture", []byte("owned bytes"))
	alias, _, _ := s.carve.Put("/owned.pcap", "alias", "fixture", []byte("alias bytes"))
	foreign, _, _ := s.carve.Put("foreign", "foreign", "fixture", []byte("foreign bytes"))
	global, _, _ := s.carve.Put("", "global", "fixture", []byte("global bytes"))
	result, err := s.handleDeleteSession(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"session_id": "owned"}}})
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	if s.carve.Get(owned.ID) != nil || s.carve.Get(alias.ID) != nil || s.carve.Get(foreign.ID) == nil || s.carve.Get(global.ID) == nil {
		t.Fatal("incorrect artifact deletion scope")
	}
	if _, err := os.Stat(owned.Path); !os.IsNotExist(err) {
		t.Fatal("owned artifact file remains")
	}
}
