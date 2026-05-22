/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// registerGraphResource exposes netcap://session/{id}/graph — a unified
// host-communication graph derived from /api/hosts + /api/connections.
// The LLM reads it once and gets nodes (hosts) + edges (aggregated
// connections), which is far cheaper than four list-call aggregations.
func (s *Server) registerGraphResource() {
	s.mcpSrv.AddResourceTemplate(
		mcplib.NewResourceTemplate(
			"netcap://session/{session_id}/graph",
			"Host communication graph",
			mcplib.WithTemplateDescription(
				"Derived host-communication graph for one session. Returns a JSON "+
					"object {nodes: [{id, ip, packets, bytes, country, ...}], edges: "+
					"[{src, dst, packets, bytes, services}]}."),
			mcplib.WithTemplateMIMEType("application/json"),
		),
		s.handleSessionGraphResource,
	)
}

func (s *Server) handleSessionGraphResource(_ context.Context, req mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
	uri := req.Params.URI
	const prefix = "netcap://session/"
	const suffix = "/graph"
	if !strings.HasPrefix(uri, prefix) || !strings.HasSuffix(uri, suffix) {
		return nil, fmt.Errorf("unexpected resource URI: %s", uri)
	}
	sessionID := strings.TrimSuffix(strings.TrimPrefix(uri, prefix), suffix)
	if sessionID == "" {
		return nil, fmt.Errorf("missing session_id in resource URI %s", uri)
	}

	ref := newSessionRef(sessionID)
	client := s.newClient()
	q := ref.sessionQueryParams()

	hostsBody, err := client.Get("/api/hosts", q)
	if err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	connsBody, err := client.Get("/api/connections", q)
	if err != nil {
		return nil, fmt.Errorf("connections: %w", err)
	}

	graph, err := buildHostGraph(hostsBody, connsBody)
	if err != nil {
		return nil, err
	}
	graph["session_id"] = sessionID
	graph["resource_uri"] = uri

	out, err := json.Marshal(graph)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	if len(out) > MaxResponseBytes {
		return nil, fmt.Errorf("graph too large (%d bytes); session has too many hosts/edges to fit", len(out))
	}
	return []mcplib.ResourceContents{
		mcplib.TextResourceContents{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(out),
		},
	}, nil
}

// buildHostGraph normalises /api/hosts + /api/connections into a single
// graph object suitable for direct LLM consumption.
//
// The webui's HostSummary / Connection shapes vary slightly per release
// so we work in map[string]any and pull only the fields we need.
func buildHostGraph(hostsBody, connsBody json.RawMessage) (map[string]any, error) {
	var hostsEnv struct {
		Hosts []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal(hostsBody, &hostsEnv); err != nil {
		return nil, fmt.Errorf("decode hosts: %w", err)
	}

	nodes := make([]map[string]any, 0, len(hostsEnv.Hosts))
	for _, h := range hostsEnv.Hosts {
		ip := firstString(h, "ip", "IP", "address")
		if ip == "" {
			continue
		}
		nodes = append(nodes, map[string]any{
			"id":      ip,
			"ip":      ip,
			"packets": h["packets"],
			"bytes":   h["bytes"],
			"country": h["country"],
			"city":    h["city"],
			"mac":     h["mac"],
		})
	}

	// /api/connections may return either a top-level array or
	// {connections: [...]}. Handle both.
	var conns []map[string]any
	if err := json.Unmarshal(connsBody, &conns); err != nil {
		var connEnv struct {
			Connections []map[string]any `json:"connections"`
		}
		if err2 := json.Unmarshal(connsBody, &connEnv); err2 != nil {
			return nil, fmt.Errorf("decode connections: %w", err)
		}
		conns = connEnv.Connections
	}

	// Aggregate connections by (src, dst) tuple for an edge view.
	type edgeAgg struct {
		Packets  int64
		Bytes    int64
		Services map[string]bool
	}
	edges := map[string]*edgeAgg{}
	for _, c := range conns {
		src := firstString(c, "srcIP", "SrcIP", "source_ip")
		dst := firstString(c, "dstIP", "DstIP", "destination_ip")
		if src == "" || dst == "" {
			continue
		}
		key := src + "->" + dst
		e := edges[key]
		if e == nil {
			e = &edgeAgg{Services: map[string]bool{}}
			edges[key] = e
		}
		e.Packets += toInt64(c["numPackets"], c["NumPackets"])
		e.Bytes += toInt64(c["totalSize"], c["TotalSize"], c["bytes"])
		if svc := firstString(c, "service", "Service"); svc != "" {
			e.Services[svc] = true
		}
	}

	edgeList := make([]map[string]any, 0, len(edges))
	for key, e := range edges {
		parts := strings.SplitN(key, "->", 2)
		svcs := make([]string, 0, len(e.Services))
		for s := range e.Services {
			svcs = append(svcs, s)
		}
		edgeList = append(edgeList, map[string]any{
			"src":      parts[0],
			"dst":      parts[1],
			"packets":  e.Packets,
			"bytes":    e.Bytes,
			"services": svcs,
		})
	}

	return map[string]any{
		"nodes":      nodes,
		"edges":      edgeList,
		"node_count": len(nodes),
		"edge_count": len(edgeList),
	}, nil
}

func toInt64(vs ...any) int64 {
	for _, v := range vs {
		switch x := v.(type) {
		case float64:
			return int64(x)
		case int:
			return int64(x)
		case int64:
			return x
		case json.Number:
			n, _ := x.Int64()
			return n
		}
	}
	return 0
}


