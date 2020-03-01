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
		return p
	}

	loc, _ := resolvers.LookupGeolocation(ipAddr)

	// create new profile
	p := &types.IPProfile{
		Addr:        ipAddr,
		NumPackets:  1,
		Geolocation: loc,
		DNSNames:    resolvers.LookupDNSNames(ipAddr),
		// Devices: []*types.DeviceProfile{
		// 	GetDeviceProfile(macAddr, i),
		// },
	}

	ipProfiles.Items[ipAddr] = p

	return p
}
