package tcp

import (
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/service"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
)

// saveTCPServiceBanner saves the banner for a TCP service to the filesystem
// and limits the length of the saved data to the BannerSize value from the config.
func saveTCPServiceBanner(s streamReader) {
	if service.Decoder.Writer == nil {
		return
	}

	// don't process empty service banners, or every probing attempt will produce a new service audit record
	if s.NumBytes() == 0 {
		return
	}

	banner := s.ServiceBanner()

	// limit length of data
	if len(banner) >= decoderconfig.Instance.BannerSize {
		banner = banner[:decoderconfig.Instance.BannerSize]
	}

	created, _ := service.ObserveFlowBanner(s.ServiceIdent(), s.Ident(), banner, s.FirstPacket(), s.NumBytes(), s.Client().NumBytes(), s.Network(), s.Transport(), "TCP")
	if created {
		streamutils.Stats.Lock()
		streamutils.Stats.NumServices++
		streamutils.Stats.Unlock()
	}
}
