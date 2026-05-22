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
	"net/http"
	"net/url"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerLifecycleTools registers session-lifecycle tools: delete a
// session and its artefacts; poll get_session_info on the server side
// so the LLM doesn't burn turns spinning on completed=false.
func (s *Server) registerLifecycleTools() error {
	tools := []server.ServerTool{
		{
			Tool: mcplib.NewTool("delete_session",
				mcplib.WithDescription(
					"Remove a session from the netcap webui and delete its on-disk "+
						"artefacts (uploads/<sid>, results/<sid>, any error log). "+
						"Available in service mode only — local mode sessions are "+
						"owned by the CLI process and cleaned up at exit."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier (service-mode hex id)."),
					mcplib.Required()),
				mcplib.WithReadOnlyHintAnnotation(false),
				mcplib.WithDestructiveHintAnnotation(true),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleDeleteSession,
		},
		{
			Tool: mcplib.NewTool("wait_for_session",
				mcplib.WithDescription(
					"Poll get_session_info server-side until the session is completed "+
						"or the timeout elapses. Returns the final session_info payload "+
						"verbatim (so the LLM can read it without an extra round-trip). "+
						"Spares the LLM from burning conversation turns on polling loops."),
				mcplib.WithString("session_id",
					mcplib.Description("Session identifier."),
					mcplib.Required()),
				mcplib.WithNumber("timeout_seconds",
					mcplib.Description("Maximum time to wait (default 60, max 300)."),
					mcplib.Max(300)),
				mcplib.WithNumber("poll_interval_ms",
					mcplib.Description("How frequently to poll (default 500, min 100, max 5000)."),
					mcplib.Max(5000)),
				mcplib.WithReadOnlyHintAnnotation(true),
				mcplib.WithDestructiveHintAnnotation(false),
				mcplib.WithIdempotentHintAnnotation(true),
				mcplib.WithOpenWorldHintAnnotation(false),
			),
			Handler: s.handleWaitForSession,
		},
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleDeleteSession(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	if ref.isPath {
		return errResult(fmt.Errorf("delete_session is service-mode only; local-mode session %q is owned by the CLI process", ref.ID)), nil
	}
	endpoint := "/api/try/session/" + url.PathEscape(ref.ID)
	body, dErr := s.deleteHTTP(endpoint)
	if dErr != nil {
		return errResult(fmt.Errorf("delete: %w", dErr)), nil
	}
	return rawJSONResult(body), nil
}

// deleteHTTP issues a DELETE against the webui's loopback API.
func (s *Server) deleteHTTP(path string) (json.RawMessage, error) {
	c := s.newClient()
	req, err := http.NewRequest(http.MethodDelete, c.BaseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := readAllLimited(resp.Body, 1<<20)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("DELETE %s: %s: %s", path, resp.Status, truncate(string(body), 500))
	}
	return body, nil
}

func (s *Server) handleWaitForSession(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	ref, err := s.requireSessionID(req)
	if err != nil {
		return errResult(err), nil
	}
	timeoutSec := req.GetInt("timeout_seconds", 60)
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	if timeoutSec > 300 {
		timeoutSec = 300
	}
	pollMs := req.GetInt("poll_interval_ms", 500)
	if pollMs < 100 {
		pollMs = 100
	}
	if pollMs > 5000 {
		pollMs = 5000
	}

	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)
	client := s.newClient()
	q := ref.sessionQueryParams()

	for {
		statsBody, sErr := client.Get("/api/audit-stats", q)
		if sErr != nil {
			return errResult(fmt.Errorf("audit-stats: %w", sErr)), nil
		}
		statusBody, _ := client.Get("/api/status", q)
		filesBody, _ := client.Get("/api/files/input", nil)

		completed := deriveCompleted(ref, filesBody, statusBody)
		if completed {
			out := map[string]any{
				"session_id":   ref.ID,
				"completed":    true,
				"audit_stats":  json.RawMessage(statsBody),
				"capture_stat": json.RawMessage(statusBody),
			}
			if errMsg, logPath, fStatus, found := extractSessionError(ref, filesBody); found {
				if errMsg != "" {
					out["error"] = errMsg
				}
				if logPath != "" {
					out["error_log_path"] = logPath
				}
				if fStatus != "" {
					out["status"] = fStatus
				}
			}
			return jsonResult(out), nil
		}

		// Surface a failed status quickly without waiting for the deadline.
		if errMsg, logPath, fStatus, found := extractSessionError(ref, filesBody); found && errMsg != "" {
			out := map[string]any{
				"session_id":     ref.ID,
				"completed":      false,
				"error":          errMsg,
				"error_log_path": logPath,
				"status":         fStatus,
			}
			return jsonResult(out), nil
		}

		if time.Now().After(deadline) {
			out := map[string]any{
				"session_id": ref.ID,
				"completed":  false,
				"timed_out":  true,
				"note":       fmt.Sprintf("session did not complete within %ds; poll get_session_info or extend the timeout", timeoutSec),
			}
			return jsonResult(out), nil
		}

		select {
		case <-ctx.Done():
			return errResult(ctx.Err()), nil
		case <-time.After(time.Duration(pollMs) * time.Millisecond):
		}
	}
}
