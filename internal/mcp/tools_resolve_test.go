/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestResolveDispatch verifies the resolve tool routes each kind to the
// right underlying resolvers function. We don't assert specific
// resolution results (the netcap DBs aren't loaded in unit tests), only
// that the tool returns a structured response without erroring.
func TestResolveDispatch(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tool := srv.mcpSrv.GetTool("resolve")
	if tool == nil {
		t.Fatal("resolve not registered")
	}

	cases := []struct {
		name string
		args map[string]any
		want []string // top-level keys that must appear
	}{
		{"dns", map[string]any{"kind": "dns", "value": "8.8.8.8"}, []string{"kind", "value", "names"}},
		{"geoip", map[string]any{"kind": "geoip", "value": "8.8.8.8"}, []string{"kind", "value", "country", "city"}},
		{"mac_vendor", map[string]any{"kind": "mac_vendor", "value": "00:00:0c:00:00:01"}, []string{"kind", "value", "vendor"}},
		{"iana_service tcp", map[string]any{"kind": "iana_service", "value": "443"}, []string{"kind", "value", "service", "port", "protocol"}},
		{"iana_service udp", map[string]any{"kind": "iana_service", "value": "53", "protocol": "udp"}, []string{"kind", "value", "service", "protocol"}},
		{"ja4", map[string]any{"kind": "ja4", "value": "t13d1516h2_8daaf6152771_b186095e22b6"}, []string{"kind", "value", "product"}},
		{"ja4s", map[string]any{"kind": "ja4s", "value": "t130200_1301_a56c5b993250"}, []string{"kind", "value", "product"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, hErr := tool.Handler(context.Background(), mcplib.CallToolRequest{
				Params: mcplib.CallToolParams{
					Name:      "resolve",
					Arguments: c.args,
				},
			})
			if hErr != nil {
				t.Fatalf("handler: %v", hErr)
			}
			if res.IsError {
				t.Fatalf("error result: %s", contentText(res))
			}
			var out map[string]any
			if jErr := json.Unmarshal([]byte(contentText(res)), &out); jErr != nil {
				t.Fatalf("decode: %v\n%s", jErr, contentText(res))
			}
			for _, k := range c.want {
				if _, ok := out[k]; !ok {
					t.Errorf("missing key %q in response: %v", k, out)
				}
			}
		})
	}
}

// TestResolveValidation rejects malformed inputs.
func TestResolveValidation(t *testing.T) {
	srv, _ := New(Options{BaseURL: "http://127.0.0.1:1"})
	tool := srv.mcpSrv.GetTool("resolve")

	bad := []map[string]any{
		{"kind": "iana_service", "value": "not-a-port"},
		{"kind": "iana_service", "value": "443", "protocol": "icmp"},
		{"kind": "bogus", "value": "x"},
		{"kind": "dns", "value": ""},
	}
	for i, args := range bad {
		res, _ := tool.Handler(context.Background(), mcplib.CallToolRequest{
			Params: mcplib.CallToolParams{Name: "resolve", Arguments: args},
		})
		if !res.IsError {
			t.Errorf("case %d: expected error result for %v, got ok", i, args)
		}
	}
}

// TestLookupDHCPFingerprintLocal returns a structured response even when
// the local DB has no match (most CI environments won't have it loaded).
func TestLookupDHCPFingerprintLocal(t *testing.T) {
	srv, _ := New(Options{BaseURL: "http://127.0.0.1:1"})
	tool := srv.mcpSrv.GetTool("lookup_dhcp_fingerprint")
	if tool == nil {
		t.Fatal("lookup_dhcp_fingerprint not registered")
	}
	res, err := tool.Handler(context.Background(), mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "lookup_dhcp_fingerprint",
			Arguments: map[string]any{"fingerprint": "1,3,6,15,33,43"},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res.IsError {
		t.Fatalf("error: %s", contentText(res))
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(contentText(res)), &out)
	if out["fingerprint"] != "1,3,6,15,33,43" {
		t.Errorf("fingerprint = %v", out["fingerprint"])
	}
	if _, hasNote := out["note"]; !hasNote {
		t.Errorf("expected 'note' field warning about network being disabled, got %v", out)
	}
}
