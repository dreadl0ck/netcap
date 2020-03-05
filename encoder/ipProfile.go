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
	"fmt"
	godpi "github.com/dreadl0ck/go-dpi"
	"github.com/dreadl0ck/ja3"
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

		flow, _ := godpi.GetPacketFlow(i.p)
		result, err := nDPI.ClassifyFlow(flow)
		if err != nil {
			fmt.Println(err)
		}
		if result != "" {
			p.Protocols[string(result)]++
			//fmt.Println("nDPI detected protocol", result)
		}

		if ja3Hash != "" {
			for _, h := range p.Ja3Hashes {
				if h == ja3Hash {
					// hash is already known, skip
					return p
				}
			}
			p.Ja3Hashes = append(p.Ja3Hashes, ja3Hash)
			p.Ja3Descriptions = append(p.Ja3Descriptions, resolvers.LookupJa3(ja3Hash))
		}

		return p
	}

	loc, _ := resolvers.LookupGeolocation(ipAddr)

	var (
		// Ja3
		hashes []string
		descriptions []string
		protos = make(map[string]uint64)
	)

	ja3Hash := ja3.DigestHexPacket(i.p)
	if ja3Hash == "" {
		ja3Hash = ja3.DigestHexPacketJa3s(i.p)
	}
	if ja3Hash != "" {
		descriptions = []string{resolvers.LookupJa3(ja3Hash)}
		hashes = []string{ja3Hash}
	}
	flow, _ := godpi.GetPacketFlow(i.p)
	result, err := nDPI.ClassifyFlow(flow)
	if err != nil {
		fmt.Println(err)
	}
	if result != "" {
		protos[string(result)]++
		//fmt.Println("nDPI detected protocol", result)
	}

	// create new profile
	p := &types.IPProfile{
		Addr:        ipAddr,
		NumPackets:  1,
		Geolocation: loc,
		DNSNames:    resolvers.LookupDNSNames(ipAddr),
		TimestampFirst: i.timestamp,
		Ja3Hashes: hashes,
		Ja3Descriptions: descriptions,
		Protocols: protos,
		// Devices: []*types.DeviceProfile{
		// 	GetDeviceProfile(macAddr, i),
		// },
	}

	ipProfiles.Items[ipAddr] = p

	return p
}
