/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// registerPrompts adds workflow "playbook" prompts. Each prompt expands
// into a single user-role message containing a numbered todo list of tool
// calls; the LLM follows it as a recipe.
func (s *Server) registerPrompts() {
	s.mcpSrv.AddPrompt(
		mcplib.Prompt{
			Name:        "triage_pcap",
			Description: "Whirlwind triage: top talkers, credentials, software, alerts, extracted files.",
			Arguments: []mcplib.PromptArgument{
				{Name: "session_id", Description: "Session id from ingest_pcap.", Required: true},
			},
		},
		s.handleTriagePrompt,
	)

	s.mcpSrv.AddPrompt(
		mcplib.Prompt{
			Name:        "investigate_host",
			Description: "Deep-dive on one host: flows, HTTP, TLS, software, carved sub-PCAP.",
			Arguments: []mcplib.PromptArgument{
				{Name: "session_id", Description: "Session id.", Required: true},
				{Name: "ip", Description: "Host IP to investigate.", Required: true},
			},
		},
		s.handleInvestigateHostPrompt,
	)

	s.mcpSrv.AddPrompt(
		mcplib.Prompt{
			Name:        "hunt_malware",
			Description: "Walk extracted files, hash them, extract IOCs, run YARA, follow up on hits.",
			Arguments: []mcplib.PromptArgument{
				{Name: "session_id", Description: "Session id.", Required: true},
			},
		},
		s.handleHuntMalwarePrompt,
	)
}

func (s *Server) handleTriagePrompt(_ context.Context, req mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
	sessionID := req.Params.Arguments["session_id"]
	text := fmt.Sprintf(`Triage PCAP session %q. Run these tools in order, summarising the noteworthy findings after each one:

1. get_session_info — confirm ingest is complete (completed=true); note total records and per-record counts.
2. list_hosts — full host inventory. Sort by bytes/packets to identify top talkers.
3. list_software limit=50 — detected software products and versions.
4. list_vulnerabilities limit=50 — CVE matches against detected software.
5. list_secrets limit=50 — plaintext credentials.
6. list_extracted_files limit=50 — files carved from traffic.
7. execute_detection_rules — run netcap rules. Then list_alerts.
8. execute_yara_scan — run YARA on extracted files. Then list_alerts search=yara.
9. list_certificates limit=50 — quick TLS posture review.
10. list_fingerprints limit=50 — JA4 fingerprint review.

Produce a final markdown report grouped by: Hosts, Software, Vulnerabilities, Credentials, Files, Alerts. Highlight any item that warrants follow-up with carve_subpcap_for_host or investigate_host.`, sessionID)

	return &mcplib.GetPromptResult{
		Messages: []mcplib.PromptMessage{
			{Role: mcplib.RoleUser, Content: mcplib.NewTextContent(text)},
		},
	}, nil
}

func (s *Server) handleInvestigateHostPrompt(_ context.Context, req mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
	sessionID := req.Params.Arguments["session_id"]
	ip := req.Params.Arguments["ip"]
	text := fmt.Sprintf(`Investigate host %q in session %q.

1. list_hosts and find the row for %s — note packet/byte totals and roles.
2. list_connections search=%q limit=200 — every connection involving %s.
3. list_http_records search=%s — HTTP activity to/from this host.
4. list_domains search=%s — DNS queries.
5. list_certificates search=%s — TLS certificates observed.
6. list_software search=%s — detected software on/for this host.
7. carve_subpcap_for_host host=%s — sub-PCAP for offline review.

Summarise: role of the host (client/server/peer), what services it offered, what services it consumed, any anomalies, and a list of suggested follow-up tools.`, ip, sessionID, ip, ip, ip, ip, ip, ip, ip, ip)

	return &mcplib.GetPromptResult{
		Messages: []mcplib.PromptMessage{
			{Role: mcplib.RoleUser, Content: mcplib.NewTextContent(text)},
		},
	}, nil
}

func (s *Server) handleHuntMalwarePrompt(_ context.Context, req mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
	sessionID := req.Params.Arguments["session_id"]
	text := fmt.Sprintf(`Hunt for malware in session %q.

1. list_extracted_files limit=200 — review carved files. Note any executables, scripts, archives, or oversized images. Capture the file_path of each suspicious entry.
2. For each suspicious file: get_extracted_file_content file_path=<path> limit=4096 — peek at the first 4 KB (returned as hex).
3. execute_yara_scan — run loaded YARA rules (synchronous; may take minutes for large sessions).
4. list_alerts search=yara — collect YARA hits.
5. For each YARA hit, identify the originating connection and call carve_subpcap_for_connection on its 4-tuple.
6. Cross-reference: list_software, list_vulnerabilities — does the host already look exploited?

Produce a markdown table of: file_path | mime | size | yara_hits | source_ip | destination_ip | recommendation.`, sessionID)

	return &mcplib.GetPromptResult{
		Messages: []mcplib.PromptMessage{
			{Role: mcplib.RoleUser, Content: mcplib.NewTextContent(text)},
		},
	}, nil
}
