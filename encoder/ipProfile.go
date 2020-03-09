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
	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/ja3"
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

// GetIPProfile fetches a known profile and updates it or returns a new one
func getIPProfile(macAddr, ipAddr string, i *idents) *types.IPProfile {

	if p, ok := ipProfiles.Items[ipAddr]; ok {
		p.NumPackets++
		p.TimestampLast = i.timestamp

		ja3Hash := ja3.DigestHexPacket(i.p)
		if ja3Hash == "" {
			ja3Hash = ja3.DigestHexPacketJa3s(i.p)
		}

		// DPI
		flow, _ := godpi.GetPacketFlow(i.p)
		results := godpi.ClassifyFlowAllModules(flow)
		for _, r := range results {
			//result := string(r.Source) + ": " + string(r.Protocol)
			result := string(r.Protocol)
			p.Protocols[result]++
		}

		dataLen := uint64(len(i.p.Data()))
		p.Bytes += dataLen

		if tl := i.p.TransportLayer(); tl != nil {
			p.SrcPorts[tl.TransportFlow().Src().String()] += dataLen
			p.DstPorts[tl.TransportFlow().Dst().String()] += dataLen
		}

		ch := tlsx.GetClientHelloBasic(i.p)
		if ch != nil {
			p.SNIs[ch.SNI]++
		}

		if ja3Hash != "" {
			if _, ok := p.Ja3[ja3Hash]; ok {
				// hash is already known, skip
				return p
			}
			p.Ja3[ja3Hash] = resolvers.LookupJa3(ja3Hash)
		}

		return p
	}

	loc, _ := resolvers.LookupGeolocation(ipAddr)

	var (
		protos = make(map[string]uint64)
		ja3Map = make(map[string]string)
	)

	ja3Hash := ja3.DigestHexPacket(i.p)
	if ja3Hash == "" {
		ja3Hash = ja3.DigestHexPacketJa3s(i.p)
	}
	if ja3Hash != "" {
		ja3Map[ja3Hash] = resolvers.LookupJa3(ja3Hash)
	}

	// DPI
	flow, _ := godpi.GetPacketFlow(i.p)
	results := godpi.ClassifyFlowAllModules(flow)
	for _, r := range results {
		//result := string(r.Source) + ": " + string(r.Protocol)
		result := string(r.Protocol)
		protos[result]++
	}

	var (
		dataLen = uint64(len(i.p.Data()))
		srcPorts = make(map[string]uint64)
		dstPorts = make(map[string]uint64)
		sniMap = make(map[string]int64)
	)

	ch := tlsx.GetClientHelloBasic(i.p)
	if ch != nil {
		sniMap[ch.SNI] = 1
	}

	if tl := i.p.TransportLayer(); tl != nil {
		srcPorts[tl.TransportFlow().Src().String()] += dataLen
		dstPorts[tl.TransportFlow().Dst().String()] += dataLen
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
