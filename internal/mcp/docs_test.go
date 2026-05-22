/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateDocs flips this test from "verify" to "rewrite". Run with
//
//	go test ./internal/mcp/ -run TestToolDocsUpToDate -update
//
// after adding, removing, or modifying a tool.
var updateDocs = flag.Bool("update", false, "rewrite docs/mcp/tools.md from the live tool registry")

// docsHeader is the static prose at the top of docs/mcp/tools.md. The
// auto-generated catalogue follows. Edit this string (not the markdown
// file directly) to change the header.
const docsHeader = `# Netcap MCP tool reference

` + "<!--- DO NOT EDIT — regenerate with: go test ./internal/mcp/ -run TestToolDocsUpToDate -update -->" + `

This catalogue is generated from the live tool registry in
` + "`internal/mcp/`" + `. Every entry corresponds to one ` + "`tools/call`" + `
name on the netcap MCP server.

Sessions
--------

A ` + "`session_id`" + ` here may be either a 32-char hex (service-mode session
selected via ` + "`/api/try/session/<id>`" + `) or an absolute filesystem path
(local-mode session selected via ` + "`/api/set-directory`" + `). The shape is
hidden behind the ` + "`session_id`" + ` argument — pass back exactly what
` + "`ingest_pcap`" + ` or ` + "`list_sessions`" + ` returns.

Response limits
---------------

- Every tool response is capped at 256 KiB. Oversized payloads come back
  as a clear error directing the LLM to paginate.
- ` + "`query_audit_records`" + ` and the list_* tools support
  ` + "`limit`" + ` / ` + "`offset`" + ` server-side.
- Long-running operations (ingest, reanalyze) return immediately and are
  polled via ` + "`get_session_info`" + ` (look at the ` + "`completed`" + `
  field). YARA scans and detection-rule executions are synchronous.

Hints
-----

Each tool exposes the standard MCP hint annotations (read-only,
destructive, idempotent, open-world). Treat them as advisory: a
` + "`destructive`" + ` tool should prompt the user before invocation.

`

// TestToolDocsUpToDate generates the canonical tool reference from the
// live registry and compares it against docs/mcp/tools.md. If the on-
// disk file is missing or stale, the test fails with a clear hint on
// how to regenerate (pass -update).
func TestToolDocsUpToDate(t *testing.T) {
	srv, err := New(Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := srv.GenerateToolDocs(docsHeader)

	path := filepath.Join("..", "..", "docs", "mcp", "tools.md")

	if *updateDocs {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("rewrote %s (%d bytes)", path, len(got))
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\n\nRun: go test ./internal/mcp/ -run TestToolDocsUpToDate -update", path, err)
	}
	if string(want) != got {
		// Spot the first diverging line for a useful failure message.
		wantLines := strings.Split(string(want), "\n")
		gotLines := strings.Split(got, "\n")
		n := len(wantLines)
		if len(gotLines) < n {
			n = len(gotLines)
		}
		var divergeAt int = n
		for i := 0; i < n; i++ {
			if wantLines[i] != gotLines[i] {
				divergeAt = i
				break
			}
		}
		t.Fatalf(`%s is stale. First difference at line %d:
on disk:  %q
expected: %q

To regenerate run:
    go test ./internal/mcp/ -run TestToolDocsUpToDate -update`,
			path, divergeAt+1,
			safeIndex(wantLines, divergeAt),
			safeIndex(gotLines, divergeAt))
	}
}

func safeIndex(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return "<eof>"
	}
	return s[i]
}
