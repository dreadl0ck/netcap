/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * JA4H - HTTP Client Fingerprint
 * Based on FoxIO-LLC JA4+ specification
 */

package ja4

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

// HTTPData contains the data needed to compute a JA4H fingerprint
type HTTPData struct {
	Method         string   // HTTP method (GET, POST, etc.)
	Version        string   // HTTP version (1.0, 1.1, 2)
	HeaderOrder    []string // Headers in wire order (names only)
	HasCookie      bool     // Whether Cookie header is present
	CookieFields   []string // Cookie field names in order
	AcceptLanguage string   // Accept-Language header value
}

// ComputeJA4H computes the JA4H fingerprint for an HTTP request
// Format: {method:2}{version:2}{cookie:1}{header_count:2}_{header_hash:12}_{cookie_hash:12}_{lang_hash:12}
// Example: ge11cn12_d6a4a8d71109_e0a89e3e939d_a82c9fccc4f7
func ComputeJA4H(data *HTTPData) string {
	ja4ha := computeJA4Ha(data)
	ja4hb := computeJA4Hb(data.HeaderOrder)
	ja4hc := computeJA4Hc(data.CookieFields)
	ja4hd := computeJA4Hd(data.AcceptLanguage)

	return fmt.Sprintf("%s_%s_%s_%s", ja4ha, ja4hb, ja4hc, ja4hd)
}

// ComputeJA4HRaw returns the unhashed JA4H fingerprint for debugging
func ComputeJA4HRaw(data *HTTPData) string {
	ja4ha := computeJA4Ha(data)
	
	// Header names joined by comma
	headerStr := strings.Join(data.HeaderOrder, ",")
	
	// Cookie fields joined by comma
	cookieStr := strings.Join(data.CookieFields, ",")
	
	return fmt.Sprintf("%s_%s_%s_%s", ja4ha, headerStr, cookieStr, data.AcceptLanguage)
}

// computeJA4Ha computes the first part of JA4H (8 characters)
// Format: {method:2}{version:2}{cookie:1}{header_count:2}
func computeJA4Ha(data *HTTPData) string {
	// Method: first 2 characters lowercase
	method := strings.ToLower(data.Method)
	if len(method) >= 2 {
		method = method[:2]
	} else if len(method) == 1 {
		method = method + "0"
	} else {
		method = "00"
	}

	// Version: 10 for HTTP/1.0, 11 for HTTP/1.1, 20 for HTTP/2, etc.
	version := httpVersionCode(data.Version)

	// Cookie presence: c if present, n if not
	cookie := "n"
	if data.HasCookie {
		cookie = "c"
	}

	// Header count (without Cookie and Referer), capped at 99
	headerCount := countHeaders(data.HeaderOrder)
	if headerCount > 99 {
		headerCount = 99
	}

	return fmt.Sprintf("%s%s%s%02d", method, version, cookie, headerCount)
}

// computeJA4Hb computes the second part of JA4H
// Truncated SHA256 hash of header names in order (comma-separated)
func computeJA4Hb(headers []string) string {
	if len(headers) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(strings.Join(headers, ","))
}

// computeJA4Hc computes the third part of JA4H
// Truncated SHA256 hash of cookie field names in order (comma-separated)
func computeJA4Hc(cookieFields []string) string {
	if len(cookieFields) == 0 {
		return "000000000000"
	}
	return truncatedSHA256(strings.Join(cookieFields, ","))
}

// computeJA4Hd computes the fourth part of JA4H
// Truncated SHA256 hash of Accept-Language value
func computeJA4Hd(acceptLanguage string) string {
	if acceptLanguage == "" {
		return "000000000000"
	}
	return truncatedSHA256(acceptLanguage)
}

// httpVersionCode returns the 2-character version code
func httpVersionCode(version string) string {
	switch version {
	case "HTTP/1.0", "1.0":
		return "10"
	case "HTTP/1.1", "1.1":
		return "11"
	case "HTTP/2.0", "HTTP/2", "2.0", "2":
		return "20"
	case "HTTP/3.0", "HTTP/3", "3.0", "3":
		return "30"
	default:
		// Try to extract version numbers
		v := strings.TrimPrefix(version, "HTTP/")
		v = strings.ReplaceAll(v, ".", "")
		// Only use if it looks like a numeric version
		if len(v) >= 2 && isDigit(v[0]) && isDigit(v[1]) {
			return v[:2]
		}
		if len(v) >= 1 && isDigit(v[0]) {
			return v[:1] + "0"
		}
		return "00"
	}
}

// isDigit checks if a byte is a digit
func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// countHeaders counts headers excluding Cookie and Referer
func countHeaders(headers []string) int {
	count := 0
	for _, h := range headers {
		lower := strings.ToLower(h)
		if lower != "cookie" && lower != "referer" {
			count++
		}
	}
	return count
}

// ExtractHeaderOrder extracts the order of HTTP headers from raw request bytes.
// This is needed because Go's net/http uses maps which randomize header order.
// Returns: header names in wire order, cookie field names in order, accept-language value
func ExtractHeaderOrder(rawRequest []byte) ([]string, []string, string) {
	var headerOrder []string
	var cookieFields []string
	var acceptLanguage string

	reader := bufio.NewReader(bytes.NewReader(rawRequest))

	// Skip request line (e.g., "GET / HTTP/1.1")
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, nil, ""
	}
	_ = line // request line not needed for header order

	// Read headers in order until we hit an empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		// Trim CRLF/LF
		line = strings.TrimRight(line, "\r\n")

		// Empty line marks end of headers
		if line == "" {
			break
		}

		// Find the colon separating header name from value
		colonIdx := strings.Index(line, ":")
		if colonIdx <= 0 {
			continue
		}

		headerName := strings.TrimSpace(line[:colonIdx])
		headerValue := strings.TrimSpace(line[colonIdx+1:])

		// Add to header order
		headerOrder = append(headerOrder, headerName)

		// Extract cookie field names if this is the Cookie header
		if strings.EqualFold(headerName, "Cookie") {
			cookieFields = parseCookieFieldNames(headerValue)
		}

		// Extract Accept-Language value
		if strings.EqualFold(headerName, "Accept-Language") {
			acceptLanguage = headerValue
		}
	}

	return headerOrder, cookieFields, acceptLanguage
}

// parseCookieFieldNames extracts the cookie field names in order from a Cookie header value
// Cookie format: "name1=value1; name2=value2; name3=value3"
func parseCookieFieldNames(cookieValue string) []string {
	var fields []string
	
	// Split by semicolon
	pairs := strings.Split(cookieValue, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		
		// Extract the field name (before =)
		eqIdx := strings.Index(pair, "=")
		if eqIdx > 0 {
			fields = append(fields, strings.TrimSpace(pair[:eqIdx]))
		} else if eqIdx == -1 {
			// Cookie without value
			fields = append(fields, pair)
		}
	}
	
	return fields
}

// ExtractHTTPDataFromRaw extracts JA4H data from raw HTTP request bytes
// This combines header order extraction with basic request line parsing
func ExtractHTTPDataFromRaw(rawRequest []byte) *HTTPData {
	data := &HTTPData{}

	reader := bufio.NewReader(bytes.NewReader(rawRequest))

	// Parse request line (e.g., "GET /path HTTP/1.1")
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return data
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) >= 1 {
		data.Method = parts[0]
	}
	if len(parts) >= 3 {
		data.Version = parts[2]
	}

	// Read headers in order
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx <= 0 {
			continue
		}

		headerName := strings.TrimSpace(line[:colonIdx])
		headerValue := strings.TrimSpace(line[colonIdx+1:])

		data.HeaderOrder = append(data.HeaderOrder, headerName)

		// Check for Cookie header
		if strings.EqualFold(headerName, "Cookie") {
			data.HasCookie = true
			data.CookieFields = parseCookieFieldNames(headerValue)
		}

		// Extract Accept-Language value
		if strings.EqualFold(headerName, "Accept-Language") {
			data.AcceptLanguage = headerValue
		}
	}

	return data
}

// ExtractHeaderOrderFromReader extracts header order from a bufio.Reader
// without consuming the entire buffer. Returns a new reader that can be
// used for subsequent parsing along with the extracted header data.
// This is useful when you want to extract header order before using http.ReadRequest
func ExtractHeaderOrderFromReader(r *bufio.Reader) (*HTTPData, []byte, error) {
	// Peek and read the entire request to extract headers
	// We need to buffer everything because we can't reset the reader
	var buf bytes.Buffer
	data := &HTTPData{}

	// Read request line
	requestLine, err := r.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	buf.WriteString(requestLine)
	requestLine = strings.TrimRight(requestLine, "\r\n")
	
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) >= 1 {
		data.Method = parts[0]
	}
	if len(parts) >= 3 {
		data.Version = parts[2]
	}

	// Read headers
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		buf.WriteString(line)

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx <= 0 {
			continue
		}

		headerName := strings.TrimSpace(line[:colonIdx])
		headerValue := strings.TrimSpace(line[colonIdx+1:])

		data.HeaderOrder = append(data.HeaderOrder, headerName)

		if strings.EqualFold(headerName, "Cookie") {
			data.HasCookie = true
			data.CookieFields = parseCookieFieldNames(headerValue)
		}

		if strings.EqualFold(headerName, "Accept-Language") {
			data.AcceptLanguage = headerValue
		}
	}

	// Read the rest of the body
	remaining, _ := r.Peek(r.Buffered())
	buf.Write(remaining)
	// Consume remaining data
	for {
		b := make([]byte, 4096)
		n, err := r.Read(b)
		if n > 0 {
			buf.Write(b[:n])
		}
		if err != nil {
			break
		}
	}

	return data, buf.Bytes(), nil
}

// ValidateJA4H checks if a JA4H fingerprint has the correct format
// Format: {7 chars}_{12 chars}_{12 chars}_{12 chars}
func ValidateJA4H(fingerprint string) bool {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		return false
	}
	// JA4H_a: 7 chars (method:2 + version:2 + cookie:1 + count:2), JA4H_b/c/d: 12 chars each
	return len(parts[0]) == 7 && len(parts[1]) == 12 && len(parts[2]) == 12 && len(parts[3]) == 12
}

// ParseJA4H parses a JA4H fingerprint into its components
func ParseJA4H(fingerprint string) (method, version, cookie string, headerCount int, headerHash, cookieHash, langHash string, err error) {
	parts := strings.Split(fingerprint, "_")
	if len(parts) != 4 {
		err = fmt.Errorf("invalid JA4H format: expected 4 parts, got %d", len(parts))
		return
	}

	if len(parts[0]) != 8 {
		err = fmt.Errorf("invalid JA4H_a length: expected 8, got %d", len(parts[0]))
		return
	}

	method = parts[0][:2]
	version = parts[0][2:4]
	cookie = parts[0][4:5]
	_, err = fmt.Sscanf(parts[0][5:], "%d", &headerCount)
	if err != nil {
		return
	}

	headerHash = parts[1]
	cookieHash = parts[2]
	langHash = parts[3]
	return
}

// BuildHTTPDataFromRequest builds HTTPData from an http.Request and raw bytes
// The raw bytes are needed for header order preservation
func BuildHTTPDataFromRequest(req *http.Request, rawBytes []byte) *HTTPData {
	// Extract header order from raw bytes
	headerOrder, cookieFields, acceptLang := ExtractHeaderOrder(rawBytes)
	
	data := &HTTPData{
		Method:         req.Method,
		Version:        req.Proto,
		HeaderOrder:    headerOrder,
		CookieFields:   cookieFields,
		AcceptLanguage: acceptLang,
	}
	
	// Check for cookie
	if _, ok := req.Header["Cookie"]; ok {
		data.HasCookie = true
	}
	
	// If accept-language wasn't extracted from raw, try from parsed request
	if data.AcceptLanguage == "" {
		data.AcceptLanguage = req.Header.Get("Accept-Language")
	}
	
	return data
}

