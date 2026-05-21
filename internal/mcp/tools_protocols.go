/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import "github.com/mark3labs/mcp-go/server"

// registerProtocolTools registers per-protocol query tools. Only
// JSON-returning endpoints are exposed; chart endpoints (HTML) are out.
func (s *Server) registerProtocolTools() error {
	tools := []server.ServerTool{
		// DNS / domains
		simpleSessionTool(s, "list_domains",
			"Domains queried in the session, with counts. Sort by count client-side for a top-N view.",
			"/api/domains", []queryArg{qLimit(500), qOffset(), qSearch()}),

		// HTTP
		simpleSessionTool(s, "list_http_records",
			"All HTTP records in the session (request + response details).",
			"/api/http", []queryArg{qLimit(500), qOffset(), qSearch()}),

		// TLS / certificates
		simpleSessionTool(s, "list_certificates",
			"All TLS certificates observed in the session (issuer, subject, sans, validity).",
			"/api/certificates", []queryArg{qLimit(500), qOffset(), qSearch()}),

		// Fingerprints (JA4/JA4S/JA4SSH)
		simpleSessionTool(s, "list_fingerprints",
			"Cryptographic fingerprints (JA4/JA4S/JA4SSH) observed in the session.",
			"/api/fingerprints", []queryArg{qLimit(500), qOffset(), qSearch()}),

		// Secrets / credentials
		simpleSessionTool(s, "list_secrets",
			"Credentials / secrets recovered from cleartext protocols.",
			"/api/secrets", []queryArg{qLimit(500), qOffset(), qSearch()}),
		simpleSessionTool(s, "list_auth_activity",
			"Authentication activity timeline (successes/failures by service).",
			"/api/auth-activity", nil),
	}

	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}
