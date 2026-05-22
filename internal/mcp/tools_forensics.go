/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/dsoprea/go-exif/v2"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"mvdan.cc/xurls/v2"
)

// MaxIOCExtractBytes caps the file size we'll process for IOC extraction.
// Carved files can be large (PE binaries, certificates, etc.); 16 MiB is
// plenty for the kinds of payloads where IOC hunting makes sense.
const MaxIOCExtractBytes = 16 << 20

// registerForensicsTools registers tools that operate on carved files
// inline: IOC extraction (URLs/domains/IPs/emails) and EXIF parsing.
// Mirrors the ToLinksFromFile / ToDomainsFromFile / ToExifDataForImage
// Maltego transforms.
func (s *Server) registerForensicsTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("extract_iocs_from_file",
				mcplib.WithDescription(
					"Scan one carved file for indicators of compromise: URLs, hostnames, "+
						"domains, IPv4/IPv6 addresses, and email addresses. By default all "+
						"kinds are returned; restrict via `kinds` (CSV of url,domain,ip,email). "+
						"File is fetched via the same path semantics as get_extracted_file_content."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("file_path",
					mcplib.Description("Relative path inside files/, as returned by list_extracted_files."),
					mcplib.Required()),
				mcplib.WithString("kinds",
					mcplib.Description("CSV of IOC kinds to extract. Allowed: url,domain,ip,email. Default: all.")),
				mcplib.WithNumber("max_per_kind",
					mcplib.Description("Cap distinct matches returned per kind (default 200, max 5000)."),
					mcplib.Max(5000)),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleExtractIOCs,
		},
		{
			Tool: mcplib.NewTool("get_image_exif",
				mcplib.WithDescription(
					"Parse EXIF metadata from a carved image file. Returns a flat list of "+
						"{ifd_path, tag_id, tag_name, type_name, value} entries. Returns an "+
						"empty list (not an error) when the file carries no EXIF segment."),
				mcplib.WithString("session_id", mcplib.Description("Session identifier."), mcplib.Required()),
				mcplib.WithString("file_path",
					mcplib.Description("Relative path inside files/, as returned by list_extracted_files."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleGetImageExif,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleExtractIOCs(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	filePath, err := req.RequireString("file_path")
	if err != nil {
		return errResult(err), nil
	}
	kindsArg := strings.ToLower(strings.TrimSpace(req.GetString("kinds", "")))
	kinds := parseIOCKinds(kindsArg)
	maxPerKind := req.GetInt("max_per_kind", 200)
	if maxPerKind <= 0 {
		maxPerKind = 200
	}
	if maxPerKind > 5000 {
		maxPerKind = 5000
	}

	data, err := s.fetchExtractedFile(ref, filePath)
	if err != nil {
		return errResult(err), nil
	}

	out := map[string]any{
		"session_id":   ref.ID,
		"file_path":    filePath,
		"size_scanned": len(data),
		"kinds":        sortedKinds(kinds),
	}
	if kinds["url"] {
		out["urls"] = uniqueLimited(xurls.Strict().FindAllString(string(data), -1), maxPerKind)
	}
	if kinds["domain"] {
		out["domains"] = uniqueLimited(domainRegex.FindAllString(string(data), -1), maxPerKind)
	}
	if kinds["ip"] {
		ips := append(ipv4Regex.FindAllString(string(data), -1), ipv6Regex.FindAllString(string(data), -1)...)
		out["ips"] = uniqueLimited(ips, maxPerKind)
	}
	if kinds["email"] {
		out["emails"] = uniqueLimited(emailRegex.FindAllString(string(data), -1), maxPerKind)
	}
	return jsonResult(out), nil
}

func (s *Server) handleGetImageExif(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	filePath, err := req.RequireString("file_path")
	if err != nil {
		return errResult(err), nil
	}

	data, err := s.fetchExtractedFile(ref, filePath)
	if err != nil {
		return errResult(err), nil
	}

	rawExif, err := exif.SearchAndExtractExif(data)
	if err != nil {
		if errors.Is(err, exif.ErrNoExif) {
			return jsonResult(map[string]any{
				"session_id": ref.ID,
				"file_path":  filePath,
				"entries":    []any{},
				"note":       "no EXIF segment present in this file",
			}), nil
		}
		return errResult(fmt.Errorf("exif extract: %w", err)), nil
	}
	entries, err := exif.GetFlatExifData(rawExif)
	if err != nil {
		return errResult(fmt.Errorf("exif flat-data: %w", err)), nil
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]any{
			"ifd_path":   e.IfdPath,
			"tag_id":     fmt.Sprintf("0x%04x", e.TagId),
			"tag_name":   e.TagName,
			"count":      e.UnitCount,
			"type_name":  e.TagTypeName,
			"value":      e.Formatted,
		})
	}
	return jsonResult(map[string]any{
		"session_id": ref.ID,
		"file_path":  filePath,
		"entries":    out,
	}), nil
}

// fetchExtractedFile pulls one carved file's bytes via the webui's
// /api/extracted-files/download/<path> endpoint (binary), under the
// caller's session.
func (s *Server) fetchExtractedFile(ref SessionRef, filePath string) ([]byte, error) {
	endpoint := "/api/extracted-files/download/" + url.PathEscape(filePath)
	body, _, err := s.newClient().GetRaw(endpoint, ref.sessionQueryParams())
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", filePath, err)
	}
	if len(body) > MaxIOCExtractBytes {
		return nil, fmt.Errorf("file too large (%d bytes); cap is %d", len(body), MaxIOCExtractBytes)
	}
	return body, nil
}

// parseIOCKinds returns a set of enabled IOC kinds. An empty input
// enables all kinds (the LLM-friendly default).
func parseIOCKinds(csv string) map[string]bool {
	if csv == "" {
		return map[string]bool{"url": true, "domain": true, "ip": true, "email": true}
	}
	out := map[string]bool{}
	for _, k := range strings.Split(csv, ",") {
		k = strings.TrimSpace(k)
		switch k {
		case "url", "domain", "ip", "email":
			out[k] = true
		}
	}
	if len(out) == 0 {
		// Caller passed only invalid kinds: fall through to defaults so
		// the response isn't silently empty.
		return map[string]bool{"url": true, "domain": true, "ip": true, "email": true}
	}
	return out
}

func sortedKinds(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniqueLimited(in []string, max int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	return out
}

// Conservative IOC regexes. xurls handles URLs proper; we add domain /
// ip / email matchers below.
var (
	// Loose domain matcher: <label>.<label>(.<label>)*; rejects trailing
	// punctuation and IP-shaped 4-octet strings. We accept up to 6 levels.
	domainRegex = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}(?:[a-z]{2,24})\b`)
	// IPv4 dotted-quad with bounded octets.
	ipv4Regex = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b`)
	// IPv6 (loose, allows :: compaction); good enough for IOC hunting.
	ipv6Regex = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}\b|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}::|::`)
	// Email: pragmatic RFC-5322 subset.
	emailRegex = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b`)
)
