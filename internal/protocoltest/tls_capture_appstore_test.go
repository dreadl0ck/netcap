//go:build appstore

package protocoltest

import (
	"context"
	"errors"
	"testing"
)

func TestAppStoreTLSExternalAdapterIsExplicitlyUnavailable(t *testing.T) {
	for _, stream := range []int{-1, 0, 7} {
		result, err := AnalyzeTLSCapture(t.Context(), "unopened.pcap", "unopened-secrets.log", stream)
		if !errors.Is(err, errTLSExternalAdapterUnavailable) || result.Version != 1 || result.Stream != stream ||
			len(result.Client) != 0 || len(result.Server) != 0 || result.ToolVersion != "" || len(result.Limitations) == 0 {
			t.Fatalf("external adapter reported success or lost its qualification: %+v %v", result, err)
		}
	}
	if _, err := TLSStreamByCommunityID(t.Context(), "unopened.pcap", "1:unopened"); !errors.Is(err, errTLSExternalAdapterUnavailable) {
		t.Fatalf("external stream selection did not report unavailability: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := AnalyzeTLSCapture(ctx, "unopened.pcap", "unopened-secrets.log", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := TLSStreamByCommunityID(ctx, "unopened.pcap", "1:unopened"); !errors.Is(err, context.Canceled) {
		t.Fatalf("stream selection cancellation lost: %v", err)
	}
}
