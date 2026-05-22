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
	"net/url"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerFileTools registers tools that deal with extracted/carved files.
func (s *Server) registerFileTools() error {
	tools := []server.ServerTool{
		simpleSessionTool(s, "list_extracted_files",
			"All files carved out of the session's traffic by netcap's file decoder. "+
				"Each entry includes MIME type, size, source/destination IPs, and a "+
				"relative path usable as `file_path` for get_extracted_file_content.",
			"/api/extracted-files", []queryArg{qLimit(500), qOffset(), qSearch()}),
		{
			Tool: mcplib.NewTool("get_extracted_file_content",
				mcplib.WithDescription(
					"Return a chunk of one extracted file's bytes, hex-encoded. "+
						"The backing endpoint paginates: offset/limit slice into the file "+
						"(limit is capped at 64 KiB per call). Use this to inspect a "+
						"suspicious carved payload before running YARA or a disassembler."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("file_path",
					mcplib.Description("Relative path of the file inside the session's files/ directory, "+
						"as returned by list_extracted_files."),
					mcplib.Required()),
				mcplib.WithNumber("offset",
					mcplib.Description("Byte offset to start reading from (default 0).")),
				mcplib.WithNumber("limit",
					mcplib.Description("Number of bytes to read (default 16384, max 65536)."),
					mcplib.Max(65536)),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleGetExtractedFileContent,
		},
	}

	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleGetExtractedFileContent(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	filePath, err := req.RequireString("file_path")
	if err != nil {
		return errResult(err), nil
	}
	offset := req.GetInt("offset", 0)
	limit := req.GetInt("limit", 16*1024)
	if limit <= 0 {
		limit = 16 * 1024
	}
	if limit > 64*1024 {
		limit = 64 * 1024
	}

	client := s.newClient()
	endpoint := "/api/extracted-files/content/" + url.PathEscape(filePath)
	q := ref.sessionQueryParams()
	q.Set("offset", fmt.Sprintf("%d", offset))
	q.Set("limit", fmt.Sprintf("%d", limit))

	raw, gErr := client.Get(endpoint, q)
	if gErr != nil {
		return errResult(fmt.Errorf("read file %s: %w", filePath, gErr)), nil
	}

	// Parse the upstream response and augment with the download URL.
	var upstream map[string]any
	if jsonErr := json.Unmarshal(raw, &upstream); jsonErr != nil {
		return errResult(fmt.Errorf("decoding content response: %w", jsonErr)), nil
	}
	upstream["session_id"] = ref.ID
	upstream["file_path"] = filePath
	upstream["download_url"] = fmt.Sprintf("%s/api/extracted-files/download/%s",
		client.BaseURL(), url.PathEscape(filePath))
	upstream["encoding"] = "hex" // documented for the LLM; the upstream API hex-encodes its 'data' field.
	return jsonResult(upstream), nil
}
