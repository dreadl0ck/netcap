/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"fmt"
	"net/url"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerCarveTools registers sub-PCAP carving tools. Each tool selects
// the session (so /api/<thing>/download-pcap can look up the input file),
// then returns the download URL. The MCP response does not contain raw
// PCAP bytes — LLMs shouldn't carry binaries; hand the URL to another
// tool (curl, Wireshark MCP, etc.) for downstream use.
func (s *Server) registerCarveTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("carve_subpcap_for_host",
				mcplib.WithDescription(
					"Produce a sub-PCAP filtered to all traffic involving one host IP. "+
						"Returns the download URL on the netcap webui."),
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
			Handler: s.makeCarveHandler("/api/http/download-pcap", "ip-pair",
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
	return nil
}

// makeCarveHandler builds a generic handler for endpoints whose only
// inputs are simple string query params (no 4-tuple). The first element
// of mcpArgs becomes the upstream query key; for multi-arg endpoints
// pass each mcpArg.
//
// Mapping rules:
//   - mcp arg "src_ip"   -> upstream "srcIP"
//   - mcp arg "src_port" -> upstream "srcPort"
//   - mcp arg "dst_ip"   -> upstream "dstIP"
//   - mcp arg "dst_port" -> upstream "dstPort"
//   - everything else passes through 1:1.
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

		client := s.newClient()
		// Selecting the session populates activeInputFile in the webui,
		// which the download-pcap handlers consult.
		if err := s.withSession(client, ref, func() error { return nil }); err != nil {
			return errResult(err), nil
		}
		dlURL := fmt.Sprintf("%s%s?%s", client.BaseURL(), endpoint, q.Encode())
		s.logger.Printf("carve %s session=%s url=%s", label, ref.ID, dlURL)
		return jsonResult(map[string]any{
			"session_id":   ref.ID,
			"kind":         label,
			"download_url": dlURL,
			"note": "GET the download_url (no auth in CLI/loopback mode; admin Bearer token in service mode) " +
				"to retrieve the carved PCAP. The endpoint shells out to tcpdump on the webui host.",
		}), nil
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

	client := s.newClient()
	if err := s.withSession(client, ref, func() error { return nil }); err != nil {
		return errResult(err), nil
	}
	dlURL := fmt.Sprintf("%s%s?%s", client.BaseURL(), endpoint, q.Encode())
	s.logger.Printf("carve %s session=%s url=%s", label, ref.ID, dlURL)
	return jsonResult(map[string]any{
		"session_id":   ref.ID,
		"kind":         label,
		"four_tuple":   fmt.Sprintf("%s:%s -> %s:%s", req.GetString("src_ip", ""), req.GetString("src_port", ""), req.GetString("dst_ip", ""), req.GetString("dst_port", "")),
		"download_url": dlURL,
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
