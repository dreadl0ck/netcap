package utils

import (
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"testing"
)

func TestLegacyHarvesterBannerDoesNotBridgeCaptureLoss(t *testing.T) {
	old := decoderconfig.Instance
	decoderconfig.Instance = &decoderconfig.Config{HarvesterBannerSize: 512}
	t.Cleanup(func() { decoderconfig.Instance = old })
	fragments := core.DataFragments{&core.StreamData{RawData: []byte("prefix")}, &core.StreamData{SkippedBytes: 12}, &core.StreamData{RawData: []byte("not-contiguous")}}
	if got := string(createBannerFromConversation(fragments)); got != "prefix" {
		t.Fatal("banner bridged capture loss", got)
	}
}
