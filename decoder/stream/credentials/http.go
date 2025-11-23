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
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// harvester for the HTTP protocol.
func httpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
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
		} else if strings.Contains(part, "nonce=") {
			params.Nonce = extractValue(part, "nonce")
		} else if strings.Contains(part, "uri=") {
			params.URI = extractValue(part, "uri")
		} else if strings.Contains(part, "qop=") {
			params.QoP = extractValue(part, "qop")
		} else if strings.Contains(part, "nc=") {
			params.NC = extractValue(part, "nc")
		} else if strings.Contains(part, "cnonce=") {
			params.CNonce = extractValue(part, "cnonce")
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
