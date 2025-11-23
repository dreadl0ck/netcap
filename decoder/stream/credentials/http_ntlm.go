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
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// httpNTLMHarvesterFunc extracts NTLM credentials from HTTP Authorization headers
// HTTP NTLM encodes the NTLMSSP messages in base64 within HTTP headers:
// - Server: WWW-Authenticate: NTLM <base64-challenge>
// - Client: Authorization: NTLM <base64-response>
// This harvester decodes the base64 and passes to the regular NTLMSSP harvester
func httpNTLMHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// Look for "Authorization: NTLM " in the HTTP headers
	authIdx := bytes.Index(data, []byte("Authorization: NTLM "))
	if authIdx == -1 {
		// Also check for "Proxy-Authorization: NTLM "
		authIdx = bytes.Index(data, []byte("Proxy-Authorization: NTLM "))
		if authIdx == -1 {
			return nil
		}
		authIdx += len("Proxy-Authorization: NTLM ")
	} else {
		authIdx += len("Authorization: NTLM ")
	}

	// Find the end of the header line (CRLF)
	lineEnd := bytes.Index(data[authIdx:], []byte("\r\n"))
	if lineEnd == -1 {
		// Try LF only
		lineEnd = bytes.Index(data[authIdx:], []byte("\n"))
		if lineEnd == -1 {
			return nil
		}
	}

	// Extract the base64-encoded NTLM message
	b64Data := bytes.TrimSpace(data[authIdx : authIdx+lineEnd])
	if len(b64Data) == 0 {
		return nil
	}

	// Decode base64 to validate it's proper NTLM data
	_, err := base64.StdEncoding.DecodeString(string(b64Data))
	if err != nil {
		// Try URL encoding
		_, err = base64.URLEncoding.DecodeString(string(b64Data))
		if err != nil {
			return nil
		}
	}

	// Check if this contains the full NTLMSSP handshake in the session data
	// We need to accumulate both Challenge and Response messages
	// For HTTP, they typically come in separate requests, so we need to scan the entire data
	return extractHTTPNTLMFromSession(data, ident, ts)
}

// extractHTTPNTLMFromSession scans the entire HTTP session for NTLM Challenge and Response
func extractHTTPNTLMFromSession(data []byte, ident string, ts time.Time) *types.Credentials {
	var (
		challenge   []byte
		authMessage []byte
	)

	// Scan for all Authorization/WWW-Authenticate headers with NTLM
	pos := 0
	for pos < len(data) {
		// Look for WWW-Authenticate: NTLM (server challenge)
		challengeIdx := bytes.Index(data[pos:], []byte("WWW-Authenticate: NTLM "))
		if challengeIdx != -1 {
			challengeIdx += pos + len("WWW-Authenticate: NTLM ")
			lineEnd := bytes.Index(data[challengeIdx:], []byte("\r\n"))
			if lineEnd == -1 {
				lineEnd = bytes.Index(data[challengeIdx:], []byte("\n"))
			}
			if lineEnd != -1 {
				b64Challenge := bytes.TrimSpace(data[challengeIdx : challengeIdx+lineEnd])
				decoded, err := base64.StdEncoding.DecodeString(string(b64Challenge))
				if err == nil && len(decoded) > 0 {
					challenge = decoded
				}
			}
		}

		// Look for Authorization: NTLM (client response)
		authIdx := bytes.Index(data[pos:], []byte("Authorization: NTLM "))
		if authIdx != -1 {
			authIdx += pos + len("Authorization: NTLM ")
			lineEnd := bytes.Index(data[authIdx:], []byte("\r\n"))
			if lineEnd == -1 {
				lineEnd = bytes.Index(data[authIdx:], []byte("\n"))
			}
			if lineEnd != -1 {
				b64Auth := bytes.TrimSpace(data[authIdx : authIdx+lineEnd])
				decoded, err := base64.StdEncoding.DecodeString(string(b64Auth))
				if err == nil && len(decoded) > 0 {
					authMessage = decoded
				}
			}
		}

		// Move forward
		if challengeIdx != -1 || authIdx != -1 {
			if challengeIdx > authIdx {
				pos = challengeIdx + 50
			} else if authIdx != -1 {
				pos = authIdx + 50
			} else {
				pos = challengeIdx + 50
			}
		} else {
			break
		}
	}

	// If we have both challenge and auth message, reconstruct and pass to NTLMSSP harvester
	if len(challenge) > 0 && len(authMessage) > 0 {
		// Create a combined data buffer with both messages
		combined := append(challenge, authMessage...)
		return ntlmsspHarvesterFunc(combined, ident, ts)
	}

	// If we only have the auth message, try to extract from it alone
	// (some implementations may work with just the Type 3 message if challenge is stored elsewhere)
	if len(authMessage) > 0 {
		return ntlmsspHarvesterFunc(authMessage, ident, ts)
	}

	return nil
}

// httpNTLMHarvester is the harvester definition for HTTP NTLM
var httpNTLMHarvester = Harvester{
	Name:          "HTTP NTLM",
	Description:   "HTTP NTLM authentication with base64 encoding - extracts NTLM challenge-response hashes",
	HarvesterFunc: httpNTLMHarvesterFunc,
}

