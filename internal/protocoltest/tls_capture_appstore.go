//go:build appstore

package protocoltest

import (
	"context"
	"errors"
)

var errTLSExternalAdapterUnavailable = errors.New("external tshark TLS analysis is unavailable in the App Store edition")

// External adapters cannot spawn a host tool from the App Store sandbox.
// Shared result types, parsers and caller-supplied analyzers remain available.
func AnalyzeTLSCapture(ctx context.Context, input, keyLog string, stream int) (TLSCaptureResult, error) {
	result := TLSCaptureResult{Version: 1, Stream: stream, Limitations: []string{errTLSExternalAdapterUnavailable.Error()}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, errTLSExternalAdapterUnavailable
}

func TLSStreamByCommunityID(ctx context.Context, input, id string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, errTLSExternalAdapterUnavailable
}
