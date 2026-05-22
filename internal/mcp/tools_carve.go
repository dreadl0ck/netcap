/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// MaxCarveBytes caps the per-call sub-PCAP size we'll buffer in memory.
// Larger carves return a "too big" error and a hint to filter further;
// shells / external tools can still hit the download_url directly.
const MaxCarveBytes = 16 << 20 // 16 MiB

// registerCarveTools registers sub-PCAP carving tools. Each handler:
//
//  1. Selects the session so /api/<thing>/download-pcap can find the
//     input file (the webui resolves activeInputFile from currentSession).
//  2. Issues GET against the download endpoint.
//  3. Persists the carved bytes via CarveStore (on-disk + in-memory).
//  4. Returns the on-disk path, size, sha256, an MCP resource URI
//     (netcap://carve/<id>) and a base64 sample of the first 4 KiB.
//
// LLMs that share a filesystem with the MCP host can open file_path
// directly; clients on a different host can fetch the resource URI to
// stream the full bytes.
func (s *Server) registerCarveTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("carve_subpcap_for_host",
				mcplib.WithDescription(
					"Produce a sub-PCAP filtered to all traffic involving one host IP. "+
						"Returns the carved file's on-disk path, sha256, and an "+
						"netcap://carve/{id} resource URI for direct byte access."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("host", mcplib.Description("Host IP (v4 or v6)."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.makeCarveHandler("/api/hosts/download-pcap", "host", []string{"host"}),
		},
		{
			Tool: mcplib.NewTool("carve_subpcap_for_connection",
				mcplib.WithDescription("Produce a sub-PCAP for a specific 4-tuple connection."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("src_ip", mcplib.Description("Source IP."), mcplib.Required()),
				mcplib.WithString("src_port", mcplib.Description("Source port."), mcplib.Required()),
				mcplib.WithString("dst_ip", mcplib.Description("Destination IP."), mcplib.Required()),
				mcplib.WithString("dst_port", mcplib.Description("Destination port."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleCarveConnection,
		},
		{
			Tool: mcplib.NewTool("carve_subpcap_for_http_pair",
				mcplib.WithDescription("Produce a sub-PCAP of all HTTP-on-TCP flows between two IPs."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("src_ip", mcplib.Description("Source IP."), mcplib.Required()),
				mcplib.WithString("dst_ip", mcplib.Description("Destination IP."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.makeCarveHandler("/api/http/download-pcap", "http_pair",
				[]string{"src_ip", "dst_ip"}),
		},
		{
			Tool: mcplib.NewTool("carve_subpcap_for_certificate",
				mcplib.WithDescription("Produce a sub-PCAP for the TCP flow that carried a given TLS certificate (identified by its 4-tuple)."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("src_ip", mcplib.Description("Source IP of the TLS flow."), mcplib.Required()),
				mcplib.WithString("src_port", mcplib.Description("Source port."), mcplib.Required()),
				mcplib.WithString("dst_ip", mcplib.Description("Destination IP."), mcplib.Required()),
				mcplib.WithString("dst_port", mcplib.Description("Destination port."), mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleCarveCertificate,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	s.registerCarveResource()
	return nil
}

// registerCarveResource wires up the netcap://carve/{id} resource so the
// LLM can fetch carved bytes by id (within the standard MCP response cap).
func (s *Server) registerCarveResource() {
	s.mcpSrv.AddResourceTemplate(
		mcplib.NewResourceTemplate(
			"netcap://carve/{id}",
			"Carved sub-PCAP",
			mcplib.WithTemplateDescription(
				"Bytes of a previously-carved sub-PCAP. Retrieve via Read with "+
					"the URI returned from any carve_subpcap_for_* tool."),
			mcplib.WithTemplateMIMEType("application/vnd.tcpdump.pcap"),
		),
		s.handleCarveResource,
	)
}

func (s *Server) handleCarveResource(_ context.Context, req mcplib.ReadResourceRequest) ([]mcplib.ResourceContents, error) {
	uri := req.Params.URI
	const prefix = "netcap://carve/"
	if len(uri) <= len(prefix) || uri[:len(prefix)] != prefix {
		return nil, fmt.Errorf("unexpected resource URI: %s", uri)
	}
	id := uri[len(prefix):]
	entry := s.carve.Get(id)
	if entry == nil {
		return nil, fmt.Errorf("carve %s not found (may have aged out; re-run the carve tool)", id)
	}
	return []mcplib.ResourceContents{
		mcplib.BlobResourceContents{
			URI:      uri,
			MIMEType: "application/vnd.tcpdump.pcap",
			Blob:     base64.StdEncoding.EncodeToString(entry.Bytes),
		},
	}, nil
}

func (s *Server) makeCarveHandler(endpoint, label string, mcpArgs []string) server.ToolHandlerFunc {
	return func(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ref, err := s.requireSessionID(req)
		if err != nil {
			return errResult(err), nil
		}
		q := url.Values{}
		for _, a := range mcpArgs {
			v, rErr := req.RequireString(a)
			if rErr != nil {
				return errResult(rErr), nil
			}
			q.Set(carveQueryKey(a), v)
		}
		return s.doCarve(ref, endpoint, label, q)
	}
}

func (s *Server) handleCarveConnection(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.carveFourTuple(req, "/api/connections/download-pcap", "connection")
}

func (s *Server) handleCarveCertificate(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return s.carveFourTuple(req, "/api/certificates/download-pcap", "certificate")
}

func (s *Server) carveFourTuple(req mcplib.CallToolRequest, endpoint, label string) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	for _, a := range []string{"src_ip", "src_port", "dst_ip", "dst_port"} {
		if _, rErr := req.RequireString(a); rErr != nil {
			return errResult(rErr), nil
		}
	}
	q := url.Values{}
	q.Set("srcIP", req.GetString("src_ip", ""))
	q.Set("srcPort", req.GetString("src_port", ""))
	q.Set("dstIP", req.GetString("dst_ip", ""))
	q.Set("dstPort", req.GetString("dst_port", ""))
	return s.doCarve(ref, endpoint, label, q)
}

// doCarve performs the actual download + store cycle and returns a
// response shaped for the LLM. The session is passed via ?sessionId= /
// ?inputFile= rather than going through /api/set-directory.
func (s *Server) doCarve(ref SessionRef, endpoint, label string, q url.Values) (*mcplib.CallToolResult, error) {
	for k, vs := range ref.sessionQueryParams() {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	client := s.newClient()
	body, ct, gErr := client.GetRaw(endpoint, q)
	if gErr != nil {
		return errResult(fmt.Errorf("download %s: %w", endpoint, gErr)), nil
	}

	source := fmt.Sprintf("%s%s?%s", client.BaseURL(), endpoint, q.Encode())
	s.logger.Printf("carve %s session=%s bytes=%d source=%s", label, ref.ID, len(body), source)

	if len(body) == 0 {
		return errResult(fmt.Errorf("carve %s: empty response (filter matched zero packets)", label)), nil
	}
	if len(body) > MaxCarveBytes {
		return errResult(fmt.Errorf(
			"carve %s: %d bytes exceeds cap of %d; narrow your filter (e.g. add a port or time range)",
			label, len(body), MaxCarveBytes)), nil
	}

	entry, uri, sErr := s.carve.Put(ref.ID, label, source, body)
	if sErr != nil {
		return errResult(fmt.Errorf("store carve: %w", sErr)), nil
	}

	sampleN := len(body)
	if sampleN > 4096 {
		sampleN = 4096
	}
	count, total := s.carve.Stats()

	return jsonResult(map[string]any{
		"session_id":   ref.ID,
		"kind":         label,
		"resource_uri": uri,
		"file_path":    entry.Path,
		"size_bytes":   entry.SizeBytes,
		"sha256":       entry.SHA256,
		"content_type": ct,
		"sample_b64":   base64.StdEncoding.EncodeToString(body[:sampleN]),
		"sample_size":  sampleN,
		"download_url": source,
		"store_stats":  map[string]any{"entries": count, "total_bytes": total},
	}), nil
}

// carveQueryKey translates an MCP-style arg name to the upstream
// webui's camelCase query parameter.
func carveQueryKey(a string) string {
	switch a {
	case "src_ip":
		return "srcIP"
	case "src_port":
		return "srcPort"
	case "dst_ip":
		return "dstIP"
	case "dst_port":
		return "dstPort"
	default:
		return a
	}
}
