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

package http

import (
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/decoder/stream/software"
	"github.com/dreadl0ck/netcap/types"
)

// header is a HTTP header structure.
type header struct {
	name  string
	value string
}

// cookie is a HTTP cookie structure.
type cookie struct {
	name  string
	value string
}

// httpMetaStore is a thread safe in-memory store for interesting HTTP artifacts.
// TODO: currently not in use, make it configurable
type httpMetaStore struct {
	sync.Mutex

	// mapped ip address to server names
	ServerNames map[string]string

	// mapped ip address to user agents
	UserAgents map[string]string

	// mapped ip address to user agents
	Vias map[string]string

	// mapped ip address to user agents
	XPoweredBy map[string]string

	// mapped ips to known header and cookies of frontend frameworks
	CMSHeaders map[string][]header
	CMSCookies map[string][]cookie
}

// global store for selected http meta information
// TODO: add a util to dump.
var httpStore = &httpMetaStore{
	ServerNames: make(map[string]string),
	UserAgents:  make(map[string]string),
	Vias:        make(map[string]string),
	XPoweredBy:  make(map[string]string),
	CMSHeaders:  make(map[string][]header),
	CMSCookies:  make(map[string][]cookie),
}

// populate the global http meta information store
// unused at the moment because too inefficient
func updateHTTPStore(h *types.HTTP) {
	// ------ LOCK the store
	httpStore.Lock()

	if h.UserAgent != "" {
		if ua, ok := httpStore.UserAgents[h.SrcIP]; ok {
			if !strings.Contains(ua, h.UserAgent) {
				httpStore.UserAgents[h.SrcIP] = ua + "| " + h.UserAgent
			}
		} else {
			httpStore.UserAgents[h.SrcIP] = h.UserAgent
		}
	}

	if h.ServerName != "" {
		if sn, ok := httpStore.ServerNames[h.DstIP]; ok {
			if !strings.Contains(sn, h.ServerName) {
				httpStore.ServerNames[h.DstIP] = sn + "| " + h.ServerName
			}
		} else {
			httpStore.ServerNames[h.DstIP] = h.ServerName
		}
	}

	if val, ok := h.ResponseHeader["Via"]; ok {
		var sn string
		if sn, ok = httpStore.Vias[h.DstIP]; ok {
			if !strings.Contains(sn, val) {
				httpStore.Vias[h.DstIP] = sn + "| " + val
			}
		} else {
			httpStore.Vias[h.DstIP] = val
		}
	}

	if val, ok := h.ResponseHeader["X-Powered-By"]; ok {
		var sn string
		if sn, ok = httpStore.XPoweredBy[h.DstIP]; ok {
			if !strings.Contains(sn, val) {
				httpStore.XPoweredBy[h.DstIP] = sn + "| " + val
			}
		} else {
			httpStore.XPoweredBy[h.DstIP] = val
		}
	}

	// Iterate over all response headers and check if they are known CMS headers.
	// If so, add them to the httpStore for the DstIP
	for key, val := range h.ResponseHeader {
		if _, ok := software.CMSHeaders[key]; ok {
			httpStore.CMSHeaders[h.DstIP] = append(httpStore.CMSHeaders[h.DstIP], header{name: key, value: val})
		}
	}

	// If HTTP instructions are sent to set a cookie used by CMSs (of other apps), add the key and possible value to the httpStore
	if toSet, ok := h.ResponseHeader["Set-Cookie"]; ok {
		var (
			parsedCookie = strings.Split(toSet, "=")
			cookieKey    = parsedCookie[0]
			cookieValue  string
		)
		if len(parsedCookie) > 1 {
			cookieValue = parsedCookie[1]
		}
		if _, ok = software.CMSCookies[cookieKey]; ok {
			httpStore.CMSCookies[h.DstIP] = append(httpStore.CMSCookies[h.DstIP], cookie{name: cookieKey, value: cookieValue})
		}
	}

	// ------ UNLOCK the store
	httpStore.Unlock()
}
