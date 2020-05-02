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
	"fmt"
	"github.com/dreadl0ck/netcap/resolvers"
	"strconv"

	"sync"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
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

func saveServiceBanner(h *tcpReader, banner []byte) {

	var (
		ident = h.parent.net.Dst().String()+":"+h.parent.transport.Dst().String()
	)

	// check if we already have a banner for the IP + Port combination
	ServiceStore.Lock()
	if _, ok := ServiceStore.Items[ident]; ok {
		ServiceStore.Unlock()

		// banner exists. nothing to do
		return
	}
	ServiceStore.Unlock()

	// nope. lets create a new one
	s := NewService(h.parent.firstPacket.String())
	s.Banner = banner
	s.IP = h.parent.net.Dst().String()
	s.Port = h.parent.transport.Dst().String()

	// set flow ident, h.parent.ident is the client flow
	s.Flow = h.ident

	dst, err := strconv.Atoi(h.parent.transport.Dst().String())
	if err == nil {
		//switch tl.LayerType() {
		//case layers.LayerTypeTCP:
			s.Protocol = "TCP"
			s.Name = resolvers.LookupServiceByPort(dst, "tcp")
		// TODO: Since this code is invoked as part of the TCP stream reassembly UDP banner grabbing is currently not supported
		//case layers.LayerTypeUDP:
		//	s.Protocol = "UDP"
		//	s.Name = resolvers.LookupServiceByPort(dst, "udp")
		//default:
		//}
	}

	// TODO: now that we have the banner, lets try to extract further information from it
	// s.Product, s.Vendor, s.Version = analyzeBanner(banner)

	// add new service
	ServiceStore.Lock()
	ServiceStore.Items[ident] = s
	ServiceStore.Unlock()

	statsMutex.Lock()
	reassemblyStats.numServices++
	statsMutex.Unlock()
}

// NewDeviceProfile creates a new device specific profile
func NewService(ts string) *Service {
	return &Service{
		Service: &types.Service{
			Timestamp: ts,
		},
	}
}

var serviceEncoder = CreateCustomEncoder(types.Type_NC_SERVICE, "Service", func(d *CustomEncoder) error {
	return nil
}, func(p gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {

	// flush writer
	if !e.writer.IsChanWriter {
		for _, c := range ServiceStore.Items {
			fmt.Println("write", c.Service.Flow)
			c.Lock()
			e.write(c.Service)
			c.Unlock()
		}
	}
	return nil
})

