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
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/tlsx"

	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

var LocalDNS = true

// AtomicIPProfileMap contains all connections and provides synchronized access
type AtomicIPProfileMap struct {
	// SrcIP to Profiles
	Items map[string]*IPProfile
	sync.Mutex
}

// Size returns the number of elements in the Items map
func (a *AtomicIPProfileMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var ipProfiles = &AtomicIPProfileMap{
	Items: make(map[string]*IPProfile),
}

type IPProfile struct {
	*types.IPProfile
	sync.Mutex
}

// GetIPProfile fetches a known profile and updates it or returns a new one
func getIPProfile(ipAddr string, i *packetInfo) *IPProfile {
	if len(ipAddr) == 0 {
		return nil
	}

	ipProfiles.Lock()
	if p, ok := ipProfiles.Items[ipAddr]; ok {
		ipProfiles.Unlock()

		p.Lock()

		p.NumPackets++
		p.TimestampLast = i.timestamp

		dataLen := uint64(len(i.p.Data()))
		p.Bytes += dataLen

		// Transport Layer
		if tl := i.p.TransportLayer(); tl != nil {

			// log.Println(i.p.NetworkLayer().NetworkFlow().String() + " " + tl.TransportFlow().String())

			if port, ok := p.SrcPorts[tl.TransportFlow().Src().String()]; ok {
				atomic.AddUint64(&port.NumTotal, dataLen)
				if tl.LayerType() == layers.LayerTypeTCP {
					atomic.AddUint64(&port.NumTCP, 1)
				} else if tl.LayerType() == layers.LayerTypeUDP {
					atomic.AddUint64(&port.NumUDP, 1)
				}
			} else {
				port := &types.Port{
					NumTotal: dataLen,
				}
				if tl.LayerType() == layers.LayerTypeTCP {
					port.NumTCP++
				} else if tl.LayerType() == layers.LayerTypeUDP {
					port.NumUDP++
				}
				p.SrcPorts[tl.TransportFlow().Src().String()] = port
			}

			if port, ok := p.DstPorts[tl.TransportFlow().Dst().String()]; ok {
				port.NumTotal += dataLen
				if tl.LayerType() == layers.LayerTypeTCP {
					port.NumTCP++
				} else if tl.LayerType() == layers.LayerTypeUDP {
					port.NumUDP++
				}
			} else {
				port := &types.Port{
					NumTotal: dataLen,
				}
				if tl.LayerType() == layers.LayerTypeTCP {
					port.NumTCP++
				} else if tl.LayerType() == layers.LayerTypeUDP {
					port.NumUDP++
				}
				p.DstPorts[tl.TransportFlow().Dst().String()] = port
			}
		}

		// Session Layer: TLS
		ch := tlsx.GetClientHelloBasic(i.p)
		if ch != nil {
			if ch.SNI != "" {
				p.SNIs[ch.SNI]++
			}
		}

		ja3Hash := ja3.DigestHexPacket(i.p)
		if ja3Hash == "" {
			ja3Hash = ja3.DigestHexPacketJa3s(i.p)
		}

		if ja3Hash != "" {
			// add hash to profile if not already present
			if _, ok := p.Ja3[ja3Hash]; !ok {
				p.Ja3[ja3Hash] = resolvers.LookupJa3(ja3Hash)
			}
		}

		// Application Layer: DPI
		uniqueResults := dpi.GetProtocols(i.p)
		for proto, res := range uniqueResults {
			// check if proto exists already
			if prot, ok := p.Protocols[proto]; ok {
				prot.Packets++
			} else {
				// add new
				p.Protocols[proto] = dpi.NewProto(&res)
			}
		}

		p.Unlock()

		return p
	}
	ipProfiles.Unlock()

	var (
		protos   = make(map[string]*types.Protocol)
		ja3Map   = make(map[string]string)
		dataLen  = uint64(len(i.p.Data()))
		srcPorts = make(map[string]*types.Port)
		dstPorts = make(map[string]*types.Port)
		sniMap   = make(map[string]int64)
	)

	// Network Layer: IP Geolocation
	loc, _ := resolvers.LookupGeolocation(ipAddr)

	// Transport Layer: Port information

	if tl := i.p.TransportLayer(); tl != nil {

		srcPort := &types.Port{
			NumTotal: dataLen,
		}

		if tl.LayerType() == layers.LayerTypeTCP {
			srcPort.NumTCP++
		} else if tl.LayerType() == layers.LayerTypeUDP {
			srcPort.NumUDP++
		}

		srcPorts[tl.TransportFlow().Src().String()] = srcPort

		dstPort := &types.Port{
			NumTotal: dataLen,
		}
		if tl.LayerType() == layers.LayerTypeTCP {
			dstPort.NumTCP++
		} else if tl.LayerType() == layers.LayerTypeUDP {
			dstPort.NumUDP++
		}
		dstPorts[tl.TransportFlow().Dst().String()] = dstPort
	}

	// Session Layer: TLS

	ja3Hash := ja3.DigestHexPacket(i.p)
	if ja3Hash == "" {
		ja3Hash = ja3.DigestHexPacketJa3s(i.p)
	}
	if ja3Hash != "" {
		ja3Map[ja3Hash] = resolvers.LookupJa3(ja3Hash)
	}

	ch := tlsx.GetClientHelloBasic(i.p)
	if ch != nil {
		sniMap[ch.SNI] = 1
	}

	// Application Layer: DPI
	uniqueResults := dpi.GetProtocols(i.p)
	for proto, res := range uniqueResults {
		protos[proto] = dpi.NewProto(&res)
	}

	var names []string
	if LocalDNS {
		if name := resolvers.LookupDNSNameLocal(ipAddr); len(name) != 0 {
			names = append(names, name)
		}
	} else {
		names = resolvers.LookupDNSNames(ipAddr)
	}

	// create new profile
	p := &IPProfile{
		IPProfile: &types.IPProfile{
			Addr:           ipAddr,
			NumPackets:     1,
			Geolocation:    loc,
			DNSNames:       names,
			TimestampFirst: i.timestamp,
			Ja3:            ja3Map,
			Protocols:      protos,
			Bytes:          dataLen,
			SrcPorts:       srcPorts,
			DstPorts:       dstPorts,
			SNIs:           sniMap,
		},
	}

	ipProfiles.Lock()
	ipProfiles.Items[ipAddr] = p
	ipProfiles.Unlock()

	return p
}
