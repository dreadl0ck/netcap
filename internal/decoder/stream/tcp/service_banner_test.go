package tcp

import (
	"testing"
	"time"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/gopacket/gopacket"
)

type bannerObservation struct {
	streamReader
	banner string
}

func (s bannerObservation) Ident() string            { return "same endpoints" }
func (s bannerObservation) ServiceIdent() string     { return "fixture" }
func (s bannerObservation) ServiceBanner() []byte    { return []byte(s.banner) }
func (s bannerObservation) FirstPacket() time.Time   { return time.Unix(0, int64(len(s.banner))) }
func (s bannerObservation) NumBytes() int            { return len(s.banner) }
func (s bannerObservation) Client() streamReader     { return bannerObservation{banner: "request"} }
func (s bannerObservation) Network() gopacket.Flow   { return gopacket.Flow{} }
func (s bannerObservation) Transport() gopacket.Flow { return gopacket.Flow{} }

func TestServiceBannerReusedFlow(t *testing.T) {
	oldConfig, oldWriter := decoderconfig.Instance, service.Decoder.Writer
	cfg := *oldConfig
	cfg.BannerSize = 512
	decoderconfig.Instance = &cfg
	service.Decoder.Writer = netio.NewAuditRecordWriter(&netio.WriterConfig{Null: true})
	service.Store.Lock()
	oldItems := service.Store.Items
	service.Store.Unlock()
	t.Cleanup(func() {
		decoderconfig.Instance, service.Decoder.Writer = oldConfig, oldWriter
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
			saveTCPServiceBanner(bannerObservation{banner: banner})
		}
		s := service.Store.Items["fixture"]
		if s.Banner != "longer banner" || s.Timestamp != 13 || s.BytesServer != 13 || s.BytesClient != 7 || len(s.Flows) != 1 {
			t.Fatalf("reverse=%v: %+v", reverse, s.Service)
		}
	}
}
