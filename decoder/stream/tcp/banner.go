package tcp

import (
	"slices"
	"strconv"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/stream/service"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/resolvers"
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

		// ensure we don't duplicate any flows
		if slices.Contains(sv.Flows, ident) {
			return
		}

		// collect the flow on the audit record
		sv.Flows = append(sv.Flows, ident)

		// if this flow had a longer response from the server then what we have previously (in case we dont have c.Banner bytes yet)
		// set this service response on the service and update the timestamp
		// more data means more information and is therefore preferred for identification purposes
		if sv.PreferObservation(banner, s.FirstPacket().UnixNano(), s.NumBytes(), s.Client().NumBytes()) {
			sv.ResetProbeMatch()
			service.MatchServiceProbes(sv, banner, ident)
		}

		return
	}
	service.Store.Unlock()

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

	// Probe matching is deliberately outside the store lock. Recheck before
	// insertion because another stream may have created the service meanwhile.
	service.Store.Lock()

	// Another stream towards the same service may have created the entry while
	// the probes above were running. Blindly overwriting it dropped the flows
	// that entry had already collected.
	if sv, ok := service.Store.Items[s.ServiceIdent()]; ok {
		service.Store.Unlock()

		sv.Lock()
		defer sv.Unlock()

		if !slices.Contains(sv.Flows, ident) {
			sv.Flows = append(sv.Flows, ident)
		}

		if sv.PreferObservation(banner, s.FirstPacket().UnixNano(), s.NumBytes(), s.Client().NumBytes()) {
			sv.ResetProbeMatch()
			service.MatchServiceProbes(sv, banner, ident)
		}

		return
	}
	service.Store.Items[s.ServiceIdent()] = serv
	service.Store.Unlock()

	streamutils.Stats.Lock()
	streamutils.Stats.NumServices++
	streamutils.Stats.Unlock()
}
