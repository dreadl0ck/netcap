/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// NetcapClient is a thin HTTP client that talks to a netcap webui.Server
// over loopback. It exists so MCP tool handlers stay 5-line transformers
// and the analytical logic remains in exactly one place (the webui handlers).
type NetcapClient struct {
	baseURL    string
	hc         *http.Client
	adminToken string
}

// BackendError preserves the HTTP status and bounded backend diagnostic body.
type BackendError struct {
	Method, Path    string
	StatusCode      int
	Body            json.RawMessage
	diagnosticLimit int
	readErr         error
}

func (e *BackendError) Error() string {
	if e.readErr != nil {
		return fmt.Sprintf("%s %s: HTTP %d: reading response: %v", e.Method, e.Path, e.StatusCode, e.readErr)
	}
	limit := e.diagnosticLimit
	if limit == 0 {
		limit = 4000
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, truncate(string(e.Body), limit))
}

func (e *BackendError) Unwrap() error { return e.readErr }

// NewNetcapClient constructs a client targeting baseURL (e.g.
// "http://127.0.0.1:54321"). The default timeout is generous (5 minutes)
// because some endpoints (YARA, reanalyze) genuinely take that long.
func NewNetcapClient(baseURL string) *NetcapClient {
	return &NetcapClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      &http.Client{Timeout: 5 * time.Minute},
	}
}

func NewAuthenticatedNetcapClient(baseURL, token string) *NetcapClient {
	c := NewNetcapClient(baseURL)
	c.adminToken = token
	if token != "" {
		c.hc.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// BaseURL returns the configured webui base URL, useful for forming
// downloadable artefact URLs in tool responses.
func (c *NetcapClient) BaseURL() string { return c.baseURL }

// Get performs GET <path>?<query> against the webui and returns the raw
// response body. Non-2xx responses are returned as errors with a truncated
// body for context.
func (c *NetcapClient) Get(path string, query url.Values) (json.RawMessage, error) {
	return c.GetContext(context.Background(), path, query)
}
func (c *NetcapClient) GetContext(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	return c.do(req)
}

// GetAs performs Get and decodes the response, returning the zero value on error.
func (c *NetcapClient) GetAs[T any](path string, query url.Values) (T, error) {
	var zero T
	raw, err := c.Get(path, query)
	if err != nil {
		return zero, err
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		return zero, fmt.Errorf("decoding GET %s response: %w", path, err)
	}
	return result, nil
}

// PostJSON sends a JSON-encoded POST request and returns the raw response.
func (c *NetcapClient) PostJSON(path string, body any) (json.RawMessage, error) {
	return c.PostJSONContext(context.Background(), path, body)
}
func (c *NetcapClient) PostJSONContext(ctx context.Context, path string, body any) (json.RawMessage, error) {
	return c.jsonContext(ctx, http.MethodPost, path, body)
}
func (c *NetcapClient) jsonContext(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

func (c *NetcapClient) postArchiveContext(ctx context.Context, path string, data []byte) (json.RawMessage, error) {
	if len(data) > 16<<20 {
		return nil, fmt.Errorf("archive exceeds 16 MiB")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/zip")
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

// PostEmpty sends a POST with no body and optional query params — used
// to trigger actions that take no body (yara scan, execute rules).
func (c *NetcapClient) PostEmpty(path string, query url.Values) (json.RawMessage, error) {
	return c.PostEmptyContext(context.Background(), path, query)
}
func (c *NetcapClient) PostEmptyContext(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

// UploadPCAP uploads a PCAP/PCAPNG file via the webui's /api/upload
// multipart endpoint. The file is streamed from disk; no in-memory copy.
func (c *NetcapClient) UploadPCAP(pcapPath string) (json.RawMessage, error) {
	return c.UploadPCAPContext(context.Background(), pcapPath)
}

func (c *NetcapClient) UploadPCAPContext(ctx context.Context, pcapPath string) (json.RawMessage, error) {
	f, size, err := openCaptureUpload(pcapPath, maxCaptureUpload)
	if err != nil {
		return nil, fmt.Errorf("opening pcap: %w", err)
	}
	defer f.Close()

	// Build the multipart body in a pipe so we don't buffer the whole file.
	pr, pw := io.Pipe()
	defer pr.Close()
	mw := multipart.NewWriter(pw)

	uploadErr := make(chan error, 1)
	go func() {
		part, err := mw.CreateFormFile("file", filepath.Base(pcapPath))
		if err == nil {
			_, err = io.CopyN(part, f, size)
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err)
		uploadErr <- err
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/upload", pr)
	if err != nil {
		_ = pr.CloseWithError(err)
		<-uploadErr
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	body, doErr := c.do(req)
	// An early backend rejection or cancellation must release the writer.
	_ = pr.CloseWithError(doErr)
	writerErr := <-uploadErr
	if doErr != nil {
		return nil, doErr
	}
	if writerErr != nil {
		return nil, fmt.Errorf("streaming upload: %w", writerErr)
	}
	return body, doErr
}

// GetRaw returns the response bytes for endpoints that don't reply in
// JSON (e.g. /api/extracted-files/download/<id> which streams binary).
func (c *NetcapClient) GetRaw(path string, query url.Values) ([]byte, string, error) {
	return c.GetRawContext(context.Background(), path, query)
}
func (c *NetcapClient) GetRawContext(ctx context.Context, path string, query url.Values) ([]byte, string, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	c.authorizeBackend(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		const diagnosticLimit = 500
		body, err := readAllLimited(resp.Body, diagnosticLimit+1)
		return nil, "", &BackendError{Method: req.Method, Path: req.URL.Path, StatusCode: resp.StatusCode, Body: body, diagnosticLimit: diagnosticLimit, readErr: err}
	}
	const maxRawResponseBytes = 16 << 20
	if resp.ContentLength > maxRawResponseBytes {
		return nil, "", fmt.Errorf("backend response exceeds %d bytes", maxRawResponseBytes)
	}
	body, err := readAllBounded(resp.Body, maxRawResponseBytes)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

func (c *NetcapClient) do(req *http.Request) (json.RawMessage, error) {
	c.authorizeBackend(req)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	body, err := readAllBounded(resp.Body, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return nil, &BackendError{Method: req.Method, Path: req.URL.Path, StatusCode: resp.StatusCode, Body: body}
	}
	return body, nil
}

func readAllBounded(r io.Reader, max int) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > max {
		return nil, fmt.Errorf("backend response exceeds %d bytes", max)
	}
	return body, nil
}

func (c *NetcapClient) authorizeBackend(req *http.Request) {
	if c.adminToken != "" && strings.HasPrefix(req.URL.String(), c.baseURL+"/api/") {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}
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
