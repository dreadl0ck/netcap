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

package encoder

import (
	"strconv"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/resolvers"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type Service struct {
	*types.Service
	sync.Mutex
}

// AtomicDeviceProfileMap contains all connections and provides synchronized access
type AtomicServiceMap struct {
	// map Server IP + Port to Service
	Items map[string]*Service
	sync.Mutex
}

// Size returns the number of elements in the Items map
func (a *AtomicServiceMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var (
	// ServiceStore hold all connections
	ServiceStore = &AtomicServiceMap{
		Items: make(map[string]*Service),
	}
)

// addInfo is util to append information to a string using a delimiter
// information will be deduplicated
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
// and limits the length of the saved data to the BannerSize value from the config
func saveTCPServiceBanner(s StreamReader) {

	banner := s.ServiceBanner()

	// limit length of data
	if len(banner) >= c.BannerSize {
		banner = banner[:c.BannerSize]
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
			sv.Timestamp = s.FirstPacket().String()
		}
		return
	}
	ServiceStore.Unlock()

	// nope. lets create a new one
	serv := NewService(s.FirstPacket().String(), s.NumBytes(), s.Client().NumBytes(), s.Network().Dst().String())
	serv.Banner = banner
	serv.IP = s.Network().Dst().String()
	serv.Port = s.Transport().Dst().String()

	// set flow ident, h.parent.ident is the client flow
	serv.Flows = []string{s.Ident()}

	dst, err := strconv.Atoi(s.Transport().Dst().String())
	if err == nil {
		serv.Protocol = "TCP"
		serv.Name = resolvers.LookupServiceByPort(dst, "tcp")
	}

	matchServiceProbes(serv, banner, s.Ident())

	// add new service
	ServiceStore.Lock()
	ServiceStore.Items[s.ServiceIdent()] = serv
	ServiceStore.Unlock()

	statsMutex.Lock()
	reassemblyStats.numServices++
	statsMutex.Unlock()
}

// NewDeviceProfile creates a new network service
func NewService(ts string, numBytesServer int, numBytesClient int, ip string) *Service {
	var host string
	if resolvers.CurrentConfig.ReverseDNS {
		host = strings.Join(resolvers.LookupDNSNames(ip), "; ")
	} else if resolvers.CurrentConfig.LocalDNS {
		host = resolvers.LookupDNSNameLocal(ip)
	}
	return &Service{
		Service: &types.Service{
			Timestamp:   ts,
			BytesServer: int32(numBytesServer),
			BytesClient: int32(numBytesClient),
			Hostname:    host,
		},
	}
}

var serviceEncoder = CreateCustomEncoder(
	types.Type_NC_Service,
	"Service",
	"A network service",
	func(d *CustomEncoder) error {
		return InitProbes()
	},
	func(p gopacket.Packet) proto.Message {
		return nil
	},
	func(e *CustomEncoder) error {

		// flush writer
		if !e.writer.IsChanWriter {
			for _, c := range ServiceStore.Items {
				c.Lock()
				e.write(c.Service)
				c.Unlock()
			}
		}
		return nil
	},
)
