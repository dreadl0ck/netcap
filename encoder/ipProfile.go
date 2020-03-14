/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/ja3"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/tlsx"
	"sync"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

// AtomicIPProfileMap contains all connections and provides synchronized access
type AtomicIPProfileMap struct {
	// SrcIP to Profiles
	Items map[string]*types.IPProfile
	sync.Mutex
}

// Size returns the number of elements in the Items map
func (a *AtomicIPProfileMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var ipProfiles = &AtomicIPProfileMap{
	Items: make(map[string]*types.IPProfile),
}

var portMu sync.Mutex

// GetIPProfile fetches a known profile and updates it or returns a new one
func getIPProfile(macAddr, ipAddr string, i *idents) *types.IPProfile {

	if p, ok := ipProfiles.Items[ipAddr]; ok {

		p.NumPackets++
		p.TimestampLast = i.timestamp

		dataLen := uint64(len(i.p.Data()))
		p.Bytes += dataLen

		// Transport Layer
		if tl := i.p.TransportLayer(); tl != nil {

			portMu.Lock()

			if port, ok := p.SrcPorts[tl.TransportFlow().Src().String()]; ok {
				port.NumTotal += dataLen
				if tl.LayerType() == layers.LayerTypeTCP {
					port.NumTCP++
				} else if tl.LayerType() == layers.LayerTypeUDP {
					port.NumUDP++
				}
			}

			if port, ok := p.DstPorts[tl.TransportFlow().Dst().String()]; ok {
				port.NumTotal += dataLen
				if tl.LayerType() == layers.LayerTypeTCP {
					port.NumTCP++
				} else if tl.LayerType() == layers.LayerTypeUDP {
					port.NumUDP++
				}
			}

			portMu.Unlock()
		}

		// Session Layer: TLS
		ch := tlsx.GetClientHelloBasic(i.p)
		if ch != nil {
			p.SNIs[ch.SNI]++
		}

		ja3Hash := ja3.DigestHexPacket(i.p)
		if ja3Hash == "" {
			ja3Hash = ja3.DigestHexPacketJa3s(i.p)
		}

		if ja3Hash != "" {
			if _, ok := p.Ja3[ja3Hash]; ok {
				// hash is already known, skip
				return p
			}
			p.Ja3[ja3Hash] = resolvers.LookupJa3(ja3Hash)
		}

		// Application Layer: DPI
		uniqueResults := dpi.GetProtocols(i.p)
		for proto := range uniqueResults {
			p.Protocols[proto]++
		}

		return p
	}

	var (
		protos = make(map[string]uint64)
		ja3Map = make(map[string]string)
		dataLen = uint64(len(i.p.Data()))
		srcPorts = make(map[string]*types.Port)
		dstPorts = make(map[string]*types.Port)
		sniMap = make(map[string]int64)
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
	for proto := range uniqueResults {
		protos[proto]++
	}

	// create new profile
	p := &types.IPProfile{
		Addr:        ipAddr,
		NumPackets:  1,
		Geolocation: loc,
		DNSNames:    resolvers.LookupDNSNames(ipAddr),
		TimestampFirst: i.timestamp,
		Ja3:       ja3Map,
		Protocols: protos,
		Bytes: dataLen,
		SrcPorts : srcPorts,
		DstPorts: dstPorts,
		SNIs: sniMap,
		// Devices: []*types.DeviceProfile{
		// 	GetDeviceProfile(macAddr, i),
		// },
	}

	ipProfiles.Items[ipAddr] = p

	return p
}
