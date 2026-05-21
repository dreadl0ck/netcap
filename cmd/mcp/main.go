/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package mcp implements the `net mcp` subcommand: a stdio Model Context
// Protocol server suitable for use by desktop LLM clients (Claude Desktop,
// Claude Code, mcp-inspector).
//
// On startup we spin up an embedded webui.Server bound to a loopback port
// (no auth, no rate limit — local-user trust). All MCP tool handlers talk
// to this loopback API so a single set of analytical implementations
// services both the browser UI and MCP clients. When the process exits,
// the embedded webui and (optionally) the temporary data directory are
// torn down.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/cmd/capture/webui"
	netcapmcp "github.com/dreadl0ck/netcap/internal/mcp"
)

// GetFlags returns the urfave/cli flag list for the `net mcp` subcommand.
func GetFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "pcap",
			Usage: "Pre-load a PCAP/PCAPNG file into a default session before serving MCP",
		},
		&cli.StringFlag{
			Name:  "data-dir",
			Usage: "Working directory for audit-record output (default: a temp dir, removed on exit)",
		},
		&cli.BoolFlag{
			Name:  "dpi",
			Usage: "Enable Deep Packet Inspection on ingest",
		},
		&cli.StringFlag{
			Name:  "bind",
			Value: "127.0.0.1:60590",
			Usage: "Loopback host:port for the embedded webui (MCP tools dial this internally)",
		},
		&cli.StringFlag{
			Name:  "allow-tools",
			Usage: "Comma-separated allow-list of tool names (empty = all)",
		},
		&cli.StringFlag{
			Name:  "deny-tools",
			Usage: "Comma-separated deny-list of tool names",
		},
		&cli.BoolFlag{
			Name:  "keep-data",
			Usage: "Do not delete the temp data dir on exit (useful for inspection)",
		},
		&cli.BoolFlag{
			Name:  "quiet",
			Usage: "Suppress diagnostic logs on stderr (default: log to stderr)",
		},
		&cli.BoolFlag{
			Name:  "debug",
			Usage: "Verbose tool-call logging on stderr",
		},
	}
}

// Flags returns the flag names for the legacy bash-completion code path.
func Flags() []string {
	out := []string{}
	for _, f := range GetFlags() {
		out = append(out, f.Names()[0])
	}
	return out
}

// Run is a compatibility wrapper for the old Run() interface.
func Run() {
	log.SetFlags(0)
	cmd := &cli.Command{
		Name:   "mcp",
		Usage:  "run a Model Context Protocol server over stdio for an existing or new analysis",
		Flags:  GetFlags(),
		Action: RunWithContext,
	}
	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext is the urfave/cli entry point. It spawns an embedded
// webui, optionally preloads a PCAP, and runs the MCP stdio loop until
// stdin is closed or the context is cancelled.
//
// IMPORTANT: in stdio mode the protocol expects JSON-RPC on stdout. All
// log output must therefore go to stderr; we set that up here.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	// stdio JSON-RPC reserves stdout. Every package that uses the stdlib
	// log package (including the embedded webui) must write to stderr.
	// We do this unconditionally to avoid any accidental contamination.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if c.Bool("quiet") {
		log.SetOutput(io.Discard)
	}

	// The MCP server's own logger. Mirrors the global one.
	var mcpLogOut io.Writer = os.Stderr
	if c.Bool("quiet") {
		mcpLogOut = io.Discard
	}
	mcpLog := log.New(mcpLogOut, "[MCP] ", log.LstdFlags|log.Lmicroseconds)

	bind := c.String("bind")
	dataDir := c.String("data-dir")
	cleanup := false
	if dataDir == "" {
		d, err := os.MkdirTemp("", "netcap-mcp-*")
		if err != nil {
			return fmt.Errorf("creating data dir: %w", err)
		}
		dataDir = d
		cleanup = !c.Bool("keep-data")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("ensuring data dir %s: %w", dataDir, err)
	}
	defer func() {
		if cleanup {
			if err := os.RemoveAll(dataDir); err != nil {
				mcpLog.Printf("warn: removing data dir %s: %v", dataDir, err)
			}
		}
	}()

	mcpLog.Printf("starting embedded webui on %s (data dir: %s, dpi: %v)",
		bind, dataDir, c.Bool("dpi"))

	webSrv := webui.NewServer(
		bind, dataDir, nil /*inputFiles*/, "" /*assetsPath*/, c.Bool("debug"), c.Bool("dpi"),
		false /*isServiceMode*/, nil /*serviceConfig*/, nil /*runtimeConfig*/, false, /*devMode*/
	)
	if err := webSrv.Start(); err != nil {
		return fmt.Errorf("starting embedded webui: %w", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := webSrv.Stop(stopCtx); err != nil {
			mcpLog.Printf("warn: stopping webui: %v", err)
		}
	}()

	baseURL := "http://" + bind

	// Wait for the embedded webui to be ready. We probe /api/version
	// up to 30 times at 100 ms intervals (~3 s budget) so slow CI hosts
	// don't race the first MCP request against an un-bound listener.
	if err := waitForServer(baseURL); err != nil {
		return fmt.Errorf("embedded webui never became reachable on %s: %w", bind, err)
	}
	mcpLog.Printf("embedded webui ready")

	client := netcapmcp.NewNetcapClient(baseURL)

	activeSession := ""
	if pcap := c.String("pcap"); pcap != "" {
		abs, err := filepath.Abs(pcap)
		if err != nil {
			return fmt.Errorf("resolving pcap path: %w", err)
		}
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("stat pcap %s: %w", abs, err)
		}
		mcpLog.Printf("pre-loading pcap: %s", abs)
		raw, err := client.UploadPCAP(abs)
		if err != nil {
			return fmt.Errorf("preloading pcap: %w", err)
		}
		// Local-mode response is {success, id, filename, path, size}.
		// The "session id" the MCP layer uses for local mode is the
		// absolute input file path (which feeds /api/set-directory).
		var resp map[string]any
		if jErr := json.Unmarshal(raw, &resp); jErr == nil {
			if path, ok := resp["path"].(string); ok && path != "" {
				activeSession = path
				mcpLog.Printf("active session: %s", activeSession)
			} else if errMsg, ok := resp["error"].(string); ok && errMsg != "" {
				return fmt.Errorf("preload failed: %s", errMsg)
			} else {
				mcpLog.Printf("warn: upload response had no path field: %s", string(raw))
			}
		}
	}

	mcpSrv, err := netcapmcp.New(netcapmcp.Options{
		BaseURL:         baseURL,
		ActiveSession:   activeSession,
		AllowedTools:    splitCSV(c.String("allow-tools")),
		DisallowedTools: splitCSV(c.String("deny-tools")),
		Logger:          mcpLog,
	})
	if err != nil {
		return fmt.Errorf("constructing MCP server: %w", err)
	}

	mcpLog.Printf("MCP stdio server ready (active_session=%q)", activeSession)

	// Run the stdio loop. It blocks until stdin is closed or ctx is done.
	if err := mcpSrv.ServeStdio(ctx); err != nil && err != context.Canceled && err != io.EOF {
		return fmt.Errorf("serving MCP stdio: %w", err)
	}
	return nil
}

// waitForServer polls /api/version on baseURL until it answers or 3
// seconds elapse. Returns nil on success.
func waitForServer(baseURL string) error {
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	hc := &http.Client{Timeout: 500 * time.Millisecond}
	u := strings.TrimRight(baseURL, "/") + "/api/version"
	// Validate the URL once to fail fast on malformed bind.
	if _, err := url.Parse(u); err != nil {
		return err
	}
	for time.Now().Before(deadline) {
		resp, err := hc.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
