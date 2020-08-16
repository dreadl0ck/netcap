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

package decoder

import (
	"github.com/dreadl0ck/netcap/utils"
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type service struct {
	*types.Service
	sync.Mutex
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicServiceMap struct {
	// map server IP + Port to service
	Items map[string]*service
	sync.Mutex
}

// Size returns the number of elements in the Items map.
func (a *atomicServiceMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

// ServiceStore hold all connections.
var ServiceStore = &atomicServiceMap{
	Items: make(map[string]*service),
}

// addInfo is util to append information to a string using a delimiter
// information will be deduplicated.
func addInfo(old string, new string) string {
	if len(old) == 0 {
		return new
	} else if len(new) == 0 {
		return old
	} else {
		// only append info that is not already present
		if !strings.Contains(old, new) {
			var b strings.Builder
			b.WriteString(old)
			b.WriteString(" | ")
			b.WriteString(new)

			return b.String()
		}

		return old
	}
}

// saves the banner for a TCP service to the filesystem
// and limits the length of the saved data to the BannerSize value from the config.
func saveTCPServiceBanner(s streamReader) {
	banner := s.ServiceBanner()

	// limit length of data
	if len(banner) >= conf.BannerSize {
		banner = banner[:conf.BannerSize]
	}

	ident := s.Ident()

	// check if we already have a banner for the IP + Port combination
	// if multiple services have communicated with the service, we will just add the current flow
	// we will keep the first banner that reaches the size configured in c.BannerSize
	ServiceStore.Lock()
	if sv, ok := ServiceStore.Items[s.ServiceIdent()]; ok {
		defer ServiceStore.Unlock()

		// invoke the service probe matching on all streams towards this service
		matchServiceProbes(sv, banner, s.Ident())

		// ensure we dont duplicate any flows
		for _, f := range sv.Flows {
			if f == ident {
				return
			}
		}

		// collect the flow on the audit record
		sv.Flows = append(sv.Flows, ident)

		// if this flow had a longer response from the server then what we have previously (in case we dont have c.Banner bytes yet)
		// set this service response on the service and update the timestamp
		// more data means more information and is therefore preferred for identification purposes
		if len(sv.Banner) < len(banner) {
			sv.Banner = banner
			sv.Timestamp = utils.TimeToString(s.FirstPacket())
		}

		return
	}
	ServiceStore.Unlock()

	// nope. lets create a new one
	serv := newService(utils.TimeToString(s.FirstPacket()), s.NumBytes(), s.Client().NumBytes(), s.Network().Dst().String())
	serv.Banner = banner
	serv.IP = s.Network().Dst().String()
	serv.Port = s.Transport().Dst().String()

	// set flow ident, h.parent.ident is the client flow
	serv.Flows = []string{s.Ident()}

	dst, err := strconv.Atoi(s.Transport().Dst().String())
	if err == nil {
		serv.Protocol = protoTCP
		serv.Name = resolvers.LookupServiceByPort(dst, typeTCP)
	}

	matchServiceProbes(serv, banner, s.Ident())

	// add new service
	ServiceStore.Lock()
	ServiceStore.Items[s.ServiceIdent()] = serv
	ServiceStore.Unlock()

	stats.Lock()
	stats.numServices++
	stats.Unlock()
}

// newDeviceProfile creates a new network service.
func newService(ts string, numBytesServer int, numBytesClient int, ip string) *service {
	var host string
	if resolvers.CurrentConfig.ReverseDNS {
		host = strings.Join(resolvers.LookupDNSNames(ip), "; ")
	} else if resolvers.CurrentConfig.LocalDNS {
		host = resolvers.LookupDNSNameLocal(ip)
	}

	return &service{
		Service: &types.Service{
			Timestamp:   ts,
			BytesServer: int32(numBytesServer),
			BytesClient: int32(numBytesClient),
			Hostname:    host,
		},
	}
}

var serviceDecoder = newCustomDecoder(
	types.Type_NC_Service,
	"Service",
	"A network service",
	func(d *customDecoder) error {
		return initServiceProbes()
	},
	func(p gopacket.Packet) proto.Message {
		return nil
	},
	func(e *customDecoder) error {
		// flush writer
		for _, item := range ServiceStore.Items {
			item.Lock()
			e.write(item.Service)
			item.Unlock()
		}

		return nil
	},
)
