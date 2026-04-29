// Package httputil provides small HTTP-related helpers used across Netcap.
package httputil

import (
	"io"
)

// DrainAndClose fully drains and then closes the given body.
//
// Go's default http.Transport only reuses an underlying TCP connection
// (keep-alive) when the response body has been read to completion AND closed.
// Closing a partially-read body forces a fresh connection on the next request
// and adds socket churn.
//
// Safe to call with a nil body.
func DrainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
