package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

func TestSessionResourceURIsDispatchThroughSDK(t *testing.T) {
	for _, id := range []string{"0123456789abcdef0123456789abcdef", "/tmp/capture with spaces/%literal#?.pcap"} {
		t.Run(id, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if q.Get("inputFile") != id && q.Get("sessionId") != id {
					t.Errorf("resource source changed: %s", r.URL)
				}
				switch r.URL.Path {
				case "/api/audit-stats":
					io.WriteString(w, `{"totalRecords":1}`)
				case "/api/hosts":
					io.WriteString(w, `{"hosts":[]}`)
				case "/api/connections":
					io.WriteString(w, `[]`)
				default:
					w.WriteHeader(404)
				}
			}))
			defer backend.Close()
			s, err := New(Options{BaseURL: backend.URL})
			if err != nil {
				t.Fatal(err)
			}
			cli, err := client.NewInProcessClient(s.mcpSrv)
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			ctx := context.Background()
			if err := cli.Start(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := cli.Initialize(ctx, mcplib.InitializeRequest{Params: mcplib.InitializeParams{ProtocolVersion: "2025-11-25", ClientInfo: mcplib.Implementation{Name: "resource-dispatch", Version: "1"}}}); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"summary", "graph"} {
				uri := sessionResourceURI(id, kind)
				result, err := cli.ReadResource(ctx, mcplib.ReadResourceRequest{Params: mcplib.ReadResourceParams{URI: uri}})
				if err != nil || len(result.Contents) != 1 {
					t.Fatalf("SDK resource %s: %v", uri, err)
				}
			}
		})
	}
}
