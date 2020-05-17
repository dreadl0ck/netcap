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
	"encoding/hex"
	"fmt"
	"github.com/dreadl0ck/netcap/resolvers"
	"strconv"
	"strings"
	deadlock "github.com/sasha-s/go-deadlock"


	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

type Service struct {
	*types.Service
	deadlock.Mutex
}

// AtomicDeviceProfileMap contains all connections and provides synchronized access
type AtomicServiceMap struct {
	// map Server IP + Port to Service
	Items map[string]*Service
	deadlock.Mutex
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
func addInfo(old string, new string) string {
	if len(old) == 0 {
		return new
	} else if len(new) == 0 {
		return old
	} else {
		var b strings.Builder
		b.WriteString(old)
		b.WriteString(" | ")
		b.WriteString(new)
		return b.String()
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
	ServiceStore.Lock()
	if serv, ok := ServiceStore.Items[s.ServiceIdent()]; ok {
		defer ServiceStore.Unlock()

		for _, f := range serv.Flows {
			if f == ident {
				return
			}
		}

		serv.Flows = append(serv.Flows, ident)
		return
	}
	ServiceStore.Unlock()

	// nope. lets create a new one
	serv := NewService(s.FirstPacket().String(), s.NumBytes(), s.Client().NumBytes())
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

	// match banner against nmap service probes
	for _, serviceProbe := range serviceProbes {
		if c.UseRE2 {
			if m := serviceProbe.RegEx.FindStringSubmatch(string(banner)); m != nil {

				serv.Product = addInfo(serv.Product, serviceProbe.Ident)
				serv.Vendor = addInfo(serv.Vendor, serviceProbe.Vendor)
				serv.Version = addInfo(serv.Version, serviceProbe.Version)

				if strings.Contains(serviceProbe.Version, "$1") {
					if len(m) > 1 {
						serv.Version = addInfo(serv.Version, strings.Replace(serviceProbe.Version, "$1", m[1], 1))
					}
				}

				if strings.Contains(serviceProbe.Hostname, "$1") {
					if len(m) > 1 {
						serv.Notes = addInfo(serv.Notes, strings.Replace(serviceProbe.Hostname, "$1", m[1], 1))
					}
				}

				// TODO: make a group extraction util and expand all groups in all strings properly
				if strings.Contains(serviceProbe.Info, "$1") {
					if len(m) > 1 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$1", m[1], 1))
					}
				}
				if strings.Contains(serv.Product, "$2") {
					if len(m) > 2 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$2", m[2], 1))
					}
				}

				if c.Debug {
					fmt.Println("\n\nMATCH!", s.Ident())
					fmt.Println(serviceProbe, "\nBanner:", "\n"+hex.Dump(banner))
				}
			}
		} else {
			if m, err := serviceProbe.RegEx2.FindStringMatch(string(banner)); err == nil && m != nil {

				serv.Product = addInfo(serv.Product, serviceProbe.Ident)
				serv.Vendor = addInfo(serv.Vendor, serviceProbe.Vendor)
				serv.Version = addInfo(serv.Version, serviceProbe.Version)

				if strings.Contains(serviceProbe.Version, "$1") {
					if len(m.Groups()) > 1 {
						serv.Version = addInfo(serv.Version, strings.Replace(serviceProbe.Version, "$1", m.Groups()[1].Captures[0].String(), 1))
					}
				}

				// TODO: make a group extraction util
				if strings.Contains(serviceProbe.Info, "$1") {
					if len(m.Groups()) > 1 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$1", m.Groups()[1].Captures[0].String(), 1))
					}
				}
				if strings.Contains(serv.Product, "$2") {
					if len(m.Groups()) > 2 {
						serv.Product = addInfo(serv.Product, strings.Replace(serviceProbe.Info, "$2", m.Groups()[2].Captures[0].String(), 1))
					}
				}

				if c.Debug {
					fmt.Println("\nMATCH!", s.Ident())
					fmt.Println(serviceProbe, "\nBanner:", "\n"+hex.Dump(banner))
				}
			}
		}
	}

	// add new service
	ServiceStore.Lock()
	ServiceStore.Items[s.ServiceIdent()] = serv
	ServiceStore.Unlock()

	statsMutex.Lock()
	reassemblyStats.numServices++
	statsMutex.Unlock()
}

// NewDeviceProfile creates a new device specific profile
func NewService(ts string, numBytesServer int, numBytesClient int) *Service {
	return &Service{
		Service: &types.Service{
			Timestamp:   ts,
			BytesServer: int32(numBytesServer),
			BytesClient: int32(numBytesClient),
		},
	}
}

var serviceEncoder = CreateCustomEncoder(types.Type_NC_Service, "Service", func(d *CustomEncoder) error {
	return InitProbes()
}, func(p gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {

	// flush writer
	if !e.writer.IsChanWriter {
		for _, c := range ServiceStore.Items {
			c.Lock()
			e.write(c.Service)
			c.Unlock()
		}
	}
	return nil
})
