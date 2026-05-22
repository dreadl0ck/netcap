/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NetcapClient is a thin HTTP client that talks to a netcap webui.Server
// over loopback. It exists so MCP tool handlers stay 5-line transformers
// and the analytical logic remains in exactly one place (the webui handlers).
type NetcapClient struct {
	baseURL string
	hc      *http.Client
}

// NewNetcapClient constructs a client targeting baseURL (e.g.
// "http://127.0.0.1:54321"). The default timeout is generous (5 minutes)
// because some endpoints (YARA, reanalyze) genuinely take that long.
func NewNetcapClient(baseURL string) *NetcapClient {
	return &NetcapClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      &http.Client{Timeout: 5 * time.Minute},
	}
}

// BaseURL returns the configured webui base URL, useful for forming
// downloadable artefact URLs in tool responses.
func (c *NetcapClient) BaseURL() string { return c.baseURL }

// Get performs GET <path>?<query> against the webui and returns the raw
// response body. Non-2xx responses are returned as errors with a truncated
// body for context.
func (c *NetcapClient) Get(path string, query url.Values) (json.RawMessage, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	return c.do(req)
}

// PostJSON sends a JSON-encoded POST request and returns the raw response.
func (c *NetcapClient) PostJSON(path string, body any) (json.RawMessage, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

// PostForm sends an application/x-www-form-urlencoded POST.
func (c *NetcapClient) PostForm(path string, form url.Values) (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

// PostEmpty sends a POST with no body — used to trigger actions that take
// no parameters (yara scan, execute rules).
func (c *NetcapClient) PostEmpty(path string) (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

// UploadPCAP uploads a PCAP/PCAPNG file via the webui's /api/upload
// multipart endpoint. The file is streamed from disk; no in-memory copy.
func (c *NetcapClient) UploadPCAP(pcapPath string) (json.RawMessage, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("opening pcap: %w", err)
	}
	defer f.Close()

	// Build the multipart body in a pipe so we don't buffer the whole file.
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	uploadErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		defer mw.Close()
		part, err := mw.CreateFormFile("file", filepath.Base(pcapPath))
		if err != nil {
			uploadErr <- err
			return
		}
		if _, err := io.Copy(part, f); err != nil {
			uploadErr <- err
			return
		}
		uploadErr <- nil
	}()

	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/upload", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	body, doErr := c.do(req)
	if writerErr := <-uploadErr; writerErr != nil {
		return nil, fmt.Errorf("streaming upload: %w", writerErr)
	}
	return body, doErr
}

// GetRaw returns the response bytes for endpoints that don't reply in
// JSON (e.g. /api/extracted-files/download/<id> which streams binary).
func (c *NetcapClient) GetRaw(path string, query url.Values) ([]byte, string, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("GET %s: %s: %s", path, resp.Status, truncate(string(body), 500))
	}
	return body, resp.Header.Get("Content-Type"), nil
}

func (c *NetcapClient) do(req *http.Request) (json.RawMessage, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %s: %s: %s",
			req.Method, req.URL.Path, resp.Status, truncate(string(body), 500))
	}
	return body, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// readAllLimited reads up to max bytes from r. Used by callers that want
// bounded memory even if the server misbehaves.
func readAllLimited(r io.Reader, max int) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, int64(max)))
}
