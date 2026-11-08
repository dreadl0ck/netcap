package udp

import (
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	"github.com/gopacket/gopacket"
)

func TestServiceBannerReusedFlow(t *testing.T) {
	oldConfig := decoderconfig.Instance
	cfg := *oldConfig
	cfg.BannerSize = 512
	decoderconfig.Instance = &cfg
	service.Store.Lock()
	oldItems := service.Store.Items
	service.Store.Unlock()
	t.Cleanup(func() {
		decoderconfig.Instance = oldConfig
		service.Store.Lock()
		service.Store.Items = oldItems
		service.Store.Unlock()
	})
	for _, reverse := range []bool{false, true} {
		service.ResetStore()
		banners := []string{"short", "longer banner"}
		if reverse {
			banners[0], banners[1] = banners[1], banners[0]
		}
		for _, banner := range banners {
			saveUDPServiceBanner([]byte(banner), "same endpoints", "fixture", time.Unix(0, int64(len(banner))), len(banner), 7, gopacket.Flow{}, gopacket.Flow{})
		}
		s := service.Store.Items["fixture"]
		if s.Banner != "longer banner" || s.Timestamp != 13 || s.BytesServer != 13 || s.BytesClient != 7 || len(s.Flows) != 1 {
			t.Fatalf("reverse=%v: %+v", reverse, s.Service)
		}
	}
}
