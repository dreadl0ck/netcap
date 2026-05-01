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

package secret

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceHTTP = "HTTP"

var (
	reHTTPBasic  = regexp.MustCompile(`(?:.*?)HTTP(?:[\s\S]*)(?:Authorization: Basic )(.*?)\r\n`)
	reHTTPDigest = regexp.MustCompile(`(?:.*?)Authorization: Digest (.*?)\r\n`)
)

// httpHarvesterFunc is the harvester function for the HTTP protocol.
func httpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	var (
		matchesBasic  = reHTTPBasic.FindSubmatch(data)
		matchesDigest = reHTTPDigest.FindSubmatch(data)
		username      string
		password      string
	)

	if len(matchesBasic) > 1 {
		extractedData, err := base64.StdEncoding.DecodeString(string(matchesBasic[1]))
		if err != nil {
			fmt.Println("captured HTTP Basic Auth credentials, but could not decode them")
		}
		creds := strings.Split(string(extractedData), ":")
		if len(creds) >= 2 {
			username = creds[0]
			password = creds[1]
		}

		if len(username) > 1 {
			return &types.Secret{
				Timestamp: ts.UnixNano(),
				Service:   "HTTP Basic Auth",
				Flow:      ident,
				User:      username,
				Password:  password,
			}
		}
	}

	// Enhanced HTTP Digest parsing
	if len(matchesDigest) > 1 {
		digestParams := parseHTTPDigest(data)
		if digestParams != nil && digestParams.Username != "" && digestParams.Response != "" {
			// Format for Hashcat mode 11400:
			// username:realm:nonce:uri:nc:cnonce:qop:response
			hashcatFormat := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s",
				digestParams.Username,
				digestParams.Realm,
				digestParams.Nonce,
				digestParams.URI,
				digestParams.NC,
				digestParams.CNonce,
				digestParams.QoP,
				digestParams.Response,
			)

			notes := fmt.Sprintf("Method: %s, HashType: HTTP-Digest", digestParams.Method)

			return &types.Secret{
				Timestamp: ts.UnixNano(),
				Service:   "HTTP Digest",
				Flow:      ident,
				User:      digestParams.Username,
				Password:  hashcatFormat, // Store Hashcat format in password field
				Notes:     notes,
			}
		}
	}

	// Extract credentials from HTTP POST form data
	if formCreds := extractHTTPFormSecret(data, ident, ts); formCreds != nil {
		return formCreds
	}

	// Extract sensitive URL parameters (keys, tokens, etc.)
	if urlParams := extractSensitiveURLParams(data, ident, ts); urlParams != nil {
		return urlParams
	}

	// Extract session IDs from cookies in HTTP responses
	if sessionCreds := extractSessionCookies(data, ident, ts); sessionCreds != nil {
		return sessionCreds
	}

	return nil
}

type httpDigestParams struct {
	Username string
	Realm    string
	Nonce    string
	URI      string
	QoP      string
	NC       string
	CNonce   string
	Response string
	Method   string
}

// parseHTTPDigest extracts all Digest authentication parameters
func parseHTTPDigest(data []byte) *httpDigestParams {
	// Find the HTTP method
	methodEnd := bytes.IndexByte(data, ' ')
	if methodEnd == -1 || methodEnd > 10 {
		return nil
	}
	method := string(data[:methodEnd])

	// Find Authorization: Digest header
	digestIdx := bytes.Index(data, []byte("Authorization: Digest"))
	if digestIdx == -1 {
		return nil
	}

	// Extract header line
	lineEnd := bytes.Index(data[digestIdx:], []byte("\r\n"))
	if lineEnd == -1 {
		return nil
	}

	headerLine := string(data[digestIdx : digestIdx+lineEnd])

	// Remove "Authorization: Digest " prefix
	headerLine = strings.TrimPrefix(headerLine, "Authorization: Digest ")

	params := &httpDigestParams{Method: method}

	// Split by comma and parse each part
	parts := strings.SplitSeq(headerLine, ",")
	for part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "username=") {
			params.Username = extractValue(part, "username")
		} else if strings.Contains(part, "realm=") {
			params.Realm = extractValue(part, "realm")
		} else if strings.Contains(part, "cnonce=") {
			// Check cnonce BEFORE nonce because "cnonce" contains "nonce"
			params.CNonce = extractValue(part, "cnonce")
		} else if strings.Contains(part, "nonce=") {
			params.Nonce = extractValue(part, "nonce")
		} else if strings.Contains(part, "uri=") {
			params.URI = extractValue(part, "uri")
		} else if strings.Contains(part, "qop=") {
			params.QoP = extractValue(part, "qop")
		} else if strings.Contains(part, "nc=") {
			params.NC = extractValue(part, "nc")
		} else if strings.Contains(part, "response=") {
			params.Response = extractValue(part, "response")
		}
	}

	// Validate we have the minimum required fields
	if params.Username == "" || params.Response == "" {
		return nil
	}

	return params
}

// extractValue extracts the value from a key=value pair, removing quotes
func extractValue(part, key string) string {
	idx := strings.Index(part, key+"=")
	if idx == -1 {
		return ""
	}

	value := part[idx+len(key)+1:]
	value = strings.Trim(value, "\" ")
	return value
}

// httpFormUsernameFields contains common username field names in web forms
// Based on CredSLayer's HTTP_AUTH_POTENTIAL_USERNAMES list
var httpFormUsernameFields = []string{
	"log", "login", "wpname", "ahd_username", "unickname", "nickname", "user", "user_name",
	"alias", "pseudo", "email", "username", "_username", "userid", "form_loginname",
	"loginname", "login_id", "loginid", "session_key", "sessionkey", "pop_login",
	"user_id", "screename", "uname", "ulogin", "acctname", "account", "member",
	"mailaddress", "membername", "login_username", "login_email", "loginusername",
	"loginemail", "sign-in", "j_username", "identity", "usr", "mail",
}

// httpFormPasswordFields contains common password field names in web forms
// Based on CredSLayer's HTTP_AUTH_POTENTIAL_PASSWORDS list
var httpFormPasswordFields = []string{
	"ahd_password", "pass", "password", "_password", "passwd", "session_password",
	"sessionpassword", "login_password", "loginpassword", "form_pw", "userpassword",
	"upassword", "login_password", "passwort", "passwrd", "wppassword", "upasswd",
	"j_password", "pwd", "secret", "credentials", "credential", "pw",
}

// maxHTTPFormBodyLength limits the POST body size to prevent false positives on large uploads
const maxHTTPFormBodyLength = 2000

// sensitiveParamNames contains common parameter names that may contain sensitive tokens or keys
// This can be overridden by configuration
var sensitiveParamNames = []string{
	"key",
	"api_key",
	"apikey",
	"api-key",
	"token",
	"access_token",
	"accesstoken",
	"access-token",
	"auth_token",
	"authtoken",
	"auth-token",
	"bearer",
	"password",
	"passwd",
	"pass",
	"secret",
	"api_secret",
	"apisecret",
	"session",
	"sessionid",
	"session_id",
	"session-id",
	"auth",
	"authorization",
	"jwt",
	"bearer_token",
}

// getSensitiveParamNames returns the configured sensitive parameter names or defaults
func getSensitiveParamNames() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "HTTP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["sensitive_params"]; ok {
					// Convert interface{} to []string
					if paramSlice, ok := params.([]any); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return sensitiveParamNames
}

// extractSensitiveURLParams extracts potentially sensitive parameters from HTTP request URLs
func extractSensitiveURLParams(data []byte, ident string, ts time.Time) *types.Secret {
	// Look for GET or POST request line
	// Format: METHOD /path?query HTTP/1.X
	lines := bytes.SplitN(data, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return nil
	}

	requestLine := string(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil
	}

	method := parts[0]
	uri := parts[1]

	// Only process HTTP methods
	if method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
		return nil
	}

	// Check if URI contains query parameters
	if !strings.Contains(uri, "?") {
		return nil
	}

	// Parse the URL - handle both absolute and relative URLs
	var parsedURL *url.URL
	var err error

	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		parsedURL, err = url.Parse(uri)
	} else {
		// For relative URLs, parse the query string directly
		_, after, ok := strings.Cut(uri, "?")
		if !ok {
			return nil
		}
		parsedURL = &url.URL{RawQuery: after}
	}

	if err != nil {
		return nil
	}

	queryParams := parsedURL.Query()

	// Look for sensitive parameter names
	var foundParams []string
	for _, paramName := range getSensitiveParamNames() {
		if values, exists := queryParams[paramName]; exists && len(values) > 0 {
			// Get the first value if multiple exist
			value := values[0]
			// Only include if value is non-empty and looks like it could be a token/key
			// (at least 8 characters to filter out short values like "1", "true", etc.)
			if len(value) >= 8 {
				foundParams = append(foundParams, fmt.Sprintf("%s=%s", paramName, value))
			}
		}
	}

	if len(foundParams) == 0 {
		return nil
	}

	// Extract the host from the HTTP request if available
	host := extractHostFromHTTPRequest(data)

	// Create credentials record
	notes := fmt.Sprintf("Method: %s, URI: %s", method, uri)
	if host != "" {
		notes = fmt.Sprintf("Method: %s, Host: %s, URI: %s", method, host, uri)
	}

	return &types.Secret{
		Timestamp: ts.UnixNano(),
		Service:   "HTTP URL Parameter",
		Flow:      ident,
		User:      host,
		Password:  strings.Join(foundParams, "; "),
		Notes:     notes,
	}
}

// extractHostFromHTTPRequest extracts the Host header from an HTTP request
func extractHostFromHTTPRequest(data []byte) string {
	lines := bytes.SplitSeq(data, []byte("\r\n"))
	for line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			hostLine := string(line)
			parts := strings.SplitN(hostLine, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// getHTTPFormUsernameFields returns configured username field names or defaults
func getHTTPFormUsernameFields() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "HTTP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["form_username_fields"]; ok {
					if paramSlice, ok := params.([]any); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return httpFormUsernameFields
}

// getHTTPFormPasswordFields returns configured password field names or defaults
func getHTTPFormPasswordFields() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "HTTP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["form_password_fields"]; ok {
					if paramSlice, ok := params.([]any); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return httpFormPasswordFields
}

// extractHTTPFormSecret extracts username/password from HTTP POST form data
// This detects login forms submitted via application/x-www-form-urlencoded
func extractHTTPFormSecret(data []byte, ident string, ts time.Time) *types.Secret {
	// Check if this is a POST request
	if !bytes.HasPrefix(data, []byte("POST ")) {
		return nil
	}

	// Check for form content type
	lowerData := bytes.ToLower(data)
	if !bytes.Contains(lowerData, []byte("content-type: application/x-www-form-urlencoded")) &&
		!bytes.Contains(lowerData, []byte("content-type:application/x-www-form-urlencoded")) {
		return nil
	}

	// Find the body (after double CRLF)
	bodyStart := bytes.Index(data, []byte("\r\n\r\n"))
	if bodyStart == -1 {
		return nil
	}
	bodyStart += 4

	if bodyStart >= len(data) {
		return nil
	}

	body := data[bodyStart:]

	// Limit body size to prevent false positives on large uploads
	if len(body) > maxHTTPFormBodyLength {
		body = body[:maxHTTPFormBodyLength]
	}

	// Parse form data (URL-encoded: key=value&key2=value2)
	formData, err := url.ParseQuery(string(body))
	if err != nil {
		return nil
	}

	var username, password string
	var usernameField, passwordField string

	// Look for username fields
	usernameFields := getHTTPFormUsernameFields()
	for _, field := range usernameFields {
		// Check both exact match and case-insensitive
		if values, exists := formData[field]; exists && len(values) > 0 && values[0] != "" {
			username = values[0]
			usernameField = field
			break
		}
		// Try lowercase version
		if values, exists := formData[strings.ToLower(field)]; exists && len(values) > 0 && values[0] != "" {
			username = values[0]
			usernameField = strings.ToLower(field)
			break
		}
	}

	// Look for password fields
	passwordFields := getHTTPFormPasswordFields()
	for _, field := range passwordFields {
		if values, exists := formData[field]; exists && len(values) > 0 && values[0] != "" {
			password = values[0]
			passwordField = field
			break
		}
		// Try lowercase version
		if values, exists := formData[strings.ToLower(field)]; exists && len(values) > 0 && values[0] != "" {
			password = values[0]
			passwordField = strings.ToLower(field)
			break
		}
	}

	// Need at least a username to report
	if username == "" {
		return nil
	}

	// Extract additional context
	host := extractHostFromHTTPRequest(data)
	uri := extractURIFromHTTPRequest(data)

	// Build notes with context
	var notes []string
	notes = append(notes, "Method: POST")
	if host != "" {
		notes = append(notes, fmt.Sprintf("Host: %s", host))
	}
	if uri != "" {
		notes = append(notes, fmt.Sprintf("URI: %s", uri))
	}
	notes = append(notes, fmt.Sprintf("UsernameField: %s", usernameField))
	if passwordField != "" {
		notes = append(notes, fmt.Sprintf("PasswordField: %s", passwordField))
	}

	return &types.Secret{
		Timestamp: ts.UnixNano(),
		Service:   "HTTP Form Login",
		Flow:      ident,
		User:      username,
		Password:  password,
		Notes:     strings.Join(notes, ", "),
	}
}

// extractURIFromHTTPRequest extracts the request URI from an HTTP request
func extractURIFromHTTPRequest(data []byte) string {
	// Find the end of the first line
	before, _, ok := bytes.Cut(data, []byte("\r\n"))
	if !ok {
		return ""
	}

	requestLine := string(before)
	parts := strings.Fields(requestLine)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// defaultSessionCookieNames contains common session cookie names from various frameworks and platforms
var defaultSessionCookieNames = []string{
	// PHP
	"PHPSESSID",
	"phpsessid",

	// Java/J2EE
	"JSESSIONID",
	"jsessionid",

	// ASP.NET
	"ASP.NET_SessionId",
	"ASPSESSIONId",

	// Python
	"sessionid",   // Django
	"session",     // Flask
	"_session_id", // Rails-style

	// Node.js / Express
	"connect.sid",
	"express.sid",
	"sid",

	// Other common patterns
	"SESSION",
	"SESSIONID",
	"sess",
	"SESS",

	// Authentication/tracking cookies
	"auth_token",
	"authtoken",
	"auth",
	"token",
	"access_token",
}

// getSessionCookieNames returns configured session cookie names or defaults
func getSessionCookieNames() []string {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "HTTP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["session_cookie_names"]; ok {
					if paramSlice, ok := params.([]any); ok {
						result := make([]string, 0, len(paramSlice))
						for _, p := range paramSlice {
							if strParam, ok := p.(string); ok {
								result = append(result, strParam)
							}
						}
						if len(result) > 0 {
							return result
						}
					}
				}
			}
		}
	}
	return defaultSessionCookieNames
}

// getMinCookieLength returns configured minimum cookie length
func getMinCookieLength() int {
	if harvesterConfig != nil {
		for _, hConfig := range harvesterConfig.Harvesters {
			if hConfig.Name == "HTTP" && hConfig.Parameters != nil {
				if params, ok := hConfig.Parameters["min_cookie_length"]; ok {
					switch v := params.(type) {
					case int:
						return v
					case float64:
						return int(v)
					}
				}
			}
		}
	}
	return 8 // Default minimum length
}

// extractSessionCookies extracts session IDs from Set-Cookie headers in HTTP responses
func extractSessionCookies(data []byte, ident string, ts time.Time) *types.Secret {
	// Check if this is an HTTP response (starts with HTTP/1.x)
	if !bytes.HasPrefix(data, []byte("HTTP/1.")) && !bytes.HasPrefix(data, []byte("HTTP/2")) {
		return nil
	}

	lines := bytes.Split(data, []byte("\r\n"))
	if len(lines) == 0 {
		return nil
	}

	// Parse status line to get status code
	statusLine := string(lines[0])

	var foundCookies []string
	var host string

	// Parse all headers
	for i := 1; i < len(lines); i++ {
		line := lines[i]

		// Empty line indicates end of headers
		if len(line) == 0 {
			break
		}

		lineLower := bytes.ToLower(line)
		lineStr := string(line)

		// Extract Set-Cookie headers
		if bytes.HasPrefix(lineLower, []byte("set-cookie:")) {
			// Parse the cookie
			cookiePart := strings.TrimPrefix(lineStr, "Set-Cookie:")
			cookiePart = strings.TrimPrefix(cookiePart, "set-cookie:")
			cookiePart = strings.TrimSpace(cookiePart)

			// Extract cookie name and value (before first semicolon)
			cookieNameValue := cookiePart
			if before, _, ok := strings.Cut(cookiePart, ";"); ok {
				cookieNameValue = before
			}

			// Split into name=value
			parts := strings.SplitN(cookieNameValue, "=", 2)
			if len(parts) != 2 {
				continue
			}

			cookieName := strings.TrimSpace(parts[0])
			cookieValue := strings.TrimSpace(parts[1])

			// Check if this is a session cookie
			sessionNames := getSessionCookieNames()
			minLen := getMinCookieLength()
			if slices.Contains(sessionNames, cookieName) {
				// Only include if value is not empty and long enough to be a real session ID
				// Filter out "deleted" or very short values
				if len(cookieValue) >= minLen && !strings.Contains(strings.ToLower(cookieValue), "deleted") {
					foundCookies = append(foundCookies, fmt.Sprintf("%s=%s", cookieName, cookieValue))
				}
			}
		} else if bytes.HasPrefix(lineLower, []byte("host:")) {
			// Extract host if available in response (might be from request in same stream)
			host = strings.TrimSpace(strings.TrimPrefix(lineStr, "Host:"))
			host = strings.TrimSpace(strings.TrimPrefix(host, "host:"))
		} else if bytes.HasPrefix(lineLower, []byte("location:")) {
			// Try to extract host from Location header if Host header not found
			if host == "" {
				location := strings.TrimSpace(strings.TrimPrefix(lineStr, "Location:"))
				location = strings.TrimSpace(strings.TrimPrefix(location, "location:"))
				if parsedURL, err := url.Parse(location); err == nil && parsedURL.Host != "" {
					host = parsedURL.Host
				}
			}
		}
	}

	if len(foundCookies) == 0 {
		return nil
	}

	// Create credentials record
	notes := fmt.Sprintf("HTTP Response: %s", statusLine)
	if host != "" {
		notes = fmt.Sprintf("HTTP Response: %s, Host: %s", statusLine, host)
	}

	return &types.Secret{
		Timestamp: ts.UnixNano(),
		Service:   "HTTP Session Cookie",
		Flow:      ident,
		User:      host,
		Password:  strings.Join(foundCookies, "; "),
		Notes:     notes,
	}
}

// httpHarvester is the harvester definition for HTTP
var httpHarvester = Harvester{
	Name:          "HTTP",
	Description:   "HTTP authentication and form credentials - captures Basic/Digest auth, POST form logins, URL parameters, and session cookies",
	HarvesterFunc: httpHarvesterFunc,
}

// decompressHTTPBody attempts to decompress gzip-encoded HTTP response bodies.
// This is useful for extracting credentials from compressed responses.
// Returns the decompressed data or the original data if decompression fails.
func decompressHTTPBody(data []byte) []byte {
	// Check for Content-Encoding: gzip header
	if !hasGzipEncoding(data) {
		return data
	}

	// Find the body (after double CRLF)
	bodyStart := bytes.Index(data, []byte("\r\n\r\n"))
	if bodyStart == -1 {
		return data
	}
	bodyStart += 4

	if bodyStart >= len(data) {
		return data
	}

	body := data[bodyStart:]
	headers := data[:bodyStart]

	// Attempt gzip decompression
	decompressed, err := decompressGzip(body)
	if err != nil {
		// Decompression failed, return original data
		return data
	}

	// Return headers + decompressed body
	result := make([]byte, len(headers)+len(decompressed))
	copy(result, headers)
	copy(result[len(headers):], decompressed)
	return result
}

// hasGzipEncoding checks if HTTP response has Content-Encoding: gzip header
func hasGzipEncoding(data []byte) bool {
	// Check for gzip content encoding (case-insensitive)
	lowerData := bytes.ToLower(data)
	return bytes.Contains(lowerData, []byte("content-encoding: gzip")) ||
		bytes.Contains(lowerData, []byte("content-encoding:gzip"))
}

// decompressGzip decompresses gzip-encoded data
func decompressGzip(data []byte) ([]byte, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("data too short for gzip")
	}

	// Check gzip magic bytes
	if data[0] != 0x1f || data[1] != 0x8b {
		return nil, fmt.Errorf("not gzip data")
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Limit decompressed size to prevent memory issues
	const maxDecompressedSize = 10 * 1024 * 1024 // 10MB limit
	limitedReader := io.LimitReader(reader, maxDecompressedSize)

	decompressed, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}

// httpBodyCredentialPatterns contains patterns to search for in HTTP bodies
var httpBodyCredentialPatterns = []*regexp.Regexp{
	// Form-based authentication
	regexp.MustCompile(`(?i)(?:username|user|login|email)["\s:=]+["\s]*([^"&\s<>]+)`),
	regexp.MustCompile(`(?i)(?:password|pass|pwd)["\s:=]+["\s]*([^"&\s<>]+)`),
	// JSON authentication responses
	regexp.MustCompile(`(?i)"(?:token|access_token|auth_token|jwt)"[:\s]*"([^"]+)"`),
	regexp.MustCompile(`(?i)"(?:api_key|apikey|api-key)"[:\s]*"([^"]+)"`),
	// OAuth tokens
	regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*)`),
}

// extractSecretFromHTTPBody searches for credentials in HTTP response bodies
// This function handles both compressed and uncompressed bodies
func extractSecretFromHTTPBody(data []byte, ident string, ts time.Time) *types.Secret {
	// Try to decompress if gzip-encoded
	decompressedData := decompressHTTPBody(data)

	// Find the body
	_, after, ok := bytes.Cut(decompressedData, []byte("\r\n\r\n"))
	if !ok {
		return nil
	}
	body := after

	if len(body) < 10 {
		return nil
	}

	// Search for credential patterns
	for _, pattern := range httpBodyCredentialPatterns {
		if matches := pattern.FindSubmatch(body); len(matches) > 1 {
			value := string(matches[1])

			// Filter out short or obviously non-credential values
			if len(value) < 8 {
				continue
			}

			// Determine credential type from pattern
			patternStr := pattern.String()
			service := "HTTP Body"
			if strings.Contains(patternStr, "token") || strings.Contains(patternStr, "jwt") {
				service = "HTTP Token"
			} else if strings.Contains(patternStr, "api_key") {
				service = "HTTP API Key"
			} else if strings.Contains(patternStr, "Bearer") {
				service = "HTTP Bearer Token"
			}

			host := extractHostFromHTTPRequest(decompressedData)

			return &types.Secret{
				Timestamp: ts.UnixNano(),
				Service:   service,
				Flow:      ident,
				User:      host,
				Password:  value,
				Notes:     "Extracted from HTTP body (decompressed if gzip)",
			}
		}
	}

	return nil
}
