/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package credentials

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
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
func httpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
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
			return &types.Credentials{
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

			return &types.Credentials{
				Timestamp: ts.UnixNano(),
				Service:   "HTTP Digest",
				Flow:      ident,
				User:      digestParams.Username,
				Password:  hashcatFormat, // Store Hashcat format in password field
				Notes:     notes,
			}
		}
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
	parts := strings.Split(headerLine, ",")
	for _, part := range parts {
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
					if paramSlice, ok := params.([]interface{}); ok {
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
func extractSensitiveURLParams(data []byte, ident string, ts time.Time) *types.Credentials {
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
		queryStart := strings.Index(uri, "?")
		if queryStart == -1 {
			return nil
		}
		parsedURL = &url.URL{RawQuery: uri[queryStart+1:]}
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

	return &types.Credentials{
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
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
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
					if paramSlice, ok := params.([]interface{}); ok {
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
func extractSessionCookies(data []byte, ident string, ts time.Time) *types.Credentials {
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
			if idx := strings.Index(cookiePart, ";"); idx != -1 {
				cookieNameValue = cookiePart[:idx]
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
			for _, sessionName := range sessionNames {
				if cookieName == sessionName {
					// Only include if value is not empty and long enough to be a real session ID
					// Filter out "deleted" or very short values
					if len(cookieValue) >= minLen && !strings.Contains(strings.ToLower(cookieValue), "deleted") {
						foundCookies = append(foundCookies, fmt.Sprintf("%s=%s", cookieName, cookieValue))
					}
					break
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

	return &types.Credentials{
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
	Description:   "HTTP Basic/Digest authentication - captures credentials from Authorization headers",
	HarvesterFunc: httpHarvesterFunc,
}
