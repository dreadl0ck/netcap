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
	"github.com/mark3labs/mcp-go/server"
)

// registerInventoryTools registers tools that enumerate hosts, devices,
// services, and network interfaces. We only register endpoints that
// actually return JSON (not HTML chart blobs from the *_charts.go files);
// for "top N" views the LLM can client-side sort the list_* results.
func (s *Server) registerInventoryTools() error {
	tools := []server.ServerTool{
		simpleSessionTool(s, "list_hosts",
			"List all hosts (IP profiles) seen in the session, with packet and byte counts. "+
				"Use view=identity for scoped names, accounts and evidence, or view=directory for unattached directory observations. Identity availability and generation accompany every page.",
			"/api/hosts", []queryArg{{Name: "view", Description: "traffic (default), identity or directory; each view has independent pagination."}}),
		simpleSessionTool(s, "list_devices",
			"List all devices (MAC addresses) seen in the session, with vendor lookups.",
			"/api/devices", nil),
		simpleSessionTool(s, "list_services",
			"List all detected services (host+port+banner+product) in the session.",
			"/api/services", nil),
	}
	for _, t := range tools {
		if err := s.addTool(t); err != nil {
			return err
		}
	}
	return nil
}

// simpleSessionTool builds a ServerTool that takes only session_id (plus
// any extra queryArgs) and forwards to a single GET endpoint. After
// T2.1 the handler passes ?sessionId= / ?inputFile= directly so it no
// longer holds the session gate; multiple parallel tool calls against
// different sessions can now run concurrently.
func simpleSessionTool(s *Server, name, desc, endpoint string, queryArgs []queryArg) server.ServerTool {
	collectionKey, paged := pagedCollectionKeys[name]
	if paged {
		queryArgs = append([]queryArg(nil), queryArgs...)
		for _, extra := range []queryArg{qLimit(500), qOffset(), qSearch(), {Name: "fields", Description: "Optional comma-separated fields or JSON Pointer paths."}, {Name: "generation", Description: "Generation from the previous page; changed collections reject continuation."}} {
			found := false
			for _, existing := range queryArgs {
				if existing.Name == extra.Name {
					found = true
				}
			}
			if !found {
				queryArgs = append(queryArgs, extra)
			}
		}
		for i := range queryArgs {
			if queryArgs[i].Name == "limit" {
				queryArgs[i].MaxNumber = 500
			}
		}
	}
	opts := []mcplib.ToolOption{
		mcplib.WithDescription(desc),
		mcplib.WithString("session_id",
			mcplib.Description("Session identifier."),
			mcplib.Required()),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(false),
	}
	for _, qa := range queryArgs {
		opts = append(opts, qa.toolOption())
	}
	return server.ServerTool{
		Tool: mcplib.NewTool(name, opts...),
		Handler: func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			ref, err := s.requireSessionID(req)
			if err != nil {
				return errResult(err), nil
			}
			q := buildQuery(req, queryArgs)
			if paged {
				if err := collectionQuery(req, q); err != nil {
					return errResult(err), nil
				}
			}
			for k, vs := range ref.sessionQueryParams() {
				for _, v := range vs {
					q.Set(k, v)
				}
			}
			body, gErr := s.newClient().GetContext(ctx, endpoint, q)
			if gErr != nil {
				return errResult(fmt.Errorf("%s: %w", endpoint, gErr)), nil
			}
			if paged {
				return s.collectionResult(ref, collectionKey, body), nil
			}
			return rawJSONResult(body), nil
		},
	}
}
