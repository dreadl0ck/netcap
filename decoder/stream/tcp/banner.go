package tcp

import (
	"slices"
	"strconv"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
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

	ident := s.Ident()

	// check if we already have a banner for the IP + Port combination
	// if multiple services have communicated with the service, we will just add the current flow
	// we will keep the first banner that reaches the size configured in c.BannerSize
	service.Store.Lock()
	if sv, ok := service.Store.Items[s.ServiceIdent()]; ok {
		service.Store.Unlock()

		// Lock the individual service to ensure thread-safe modification
		sv.Lock()
		defer sv.Unlock()

		// invoke the service probe matching on all streams towards this service
		// TODO: make matching more banners than the first one configurable
		service.MatchServiceProbes(sv, banner, s.Ident())

		// ensure we don't duplicate any flows
		if slices.Contains(sv.Flows, ident) {
			return
		}

		// collect the flow on the audit record
		sv.Flows = append(sv.Flows, ident)

		// if this flow had a longer response from the server then what we have previously (in case we dont have c.Banner bytes yet)
		// set this service response on the service and update the timestamp
		// more data means more information and is therefore preferred for identification purposes
		if len(sv.Banner) < len(banner) {
			sv.Banner = string(banner)
			sv.Timestamp = s.FirstPacket().UnixNano()
		}

		return
	}
	service.Store.Unlock()

	// nope. lets create a new one
	// Safely extract network destination
	var networkDst string
	if len(s.Network().Dst().Raw()) > 0 {
		networkDst = s.Network().Dst().String()
	}

	serv := service.NewService(s.FirstPacket().UnixNano(), s.NumBytes(), s.Client().NumBytes(), networkDst)
	serv.Banner = string(banner)
	serv.IP = networkDst
	serv.Port = utils.DecodePort(s.Transport().Dst().Raw())

	// set flow ident, h.parent.ident is the client flow
	serv.Flows = []string{s.Ident()}

	// Safely extract transport destination port for service name lookup
	if len(s.Transport().Dst().Raw()) > 0 {
		dst, err := strconv.Atoi(s.Transport().Dst().String())
		if err == nil {
			serv.Protocol = "TCP"
			serv.Name = resolvers.LookupServiceByPort(dst, "TCP")
			serv.PortName = serv.Name // Set PortName to the same lookup result
		}
	}

	service.MatchServiceProbes(serv, banner, s.Ident())

	// add new service
	service.Store.Lock()
	service.Store.Items[s.ServiceIdent()] = serv
	service.Store.Unlock()

	streamutils.Stats.Lock()
	streamutils.Stats.NumServices++
	streamutils.Stats.Unlock()
}
