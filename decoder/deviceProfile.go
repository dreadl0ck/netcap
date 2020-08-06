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
	"log"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type deviceProfile struct {
	*types.DeviceProfile
	sync.Mutex
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicDeviceProfileMap struct {
	// SrcMAC to Profiles
	Items map[string]*deviceProfile
	sync.Mutex
}

// Size returns the number of elements in the Items map.
func (a *atomicDeviceProfileMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var (
	// Profiles hold all connections.
	Profiles = &atomicDeviceProfileMap{
		Items: make(map[string]*deviceProfile),
	}
	profileDecoderInstance *customDecoder
	profiles               int64

	// flags for flushing intervals - no flushing for now.
	// flagProfileFlushInterval = flag.Int("profile-flush-interval", 10000, "flush connections every X flows").

	// profileFlushInterval int64
	// profileTimeOut       time.Duration.
)

// GetDeviceProfile fetches a known profile and updates it or returns a new one.
func getDeviceProfile(macAddr string, i *packetInfo) *deviceProfile {
	Profiles.Lock()
	if p, ok := Profiles.Items[macAddr]; ok {
		Profiles.Unlock()
		applyDeviceProfileUpdate(p, i)
		return p
	}
	Profiles.Unlock()

	// create new profile
	p := newDeviceProfile(i)

	Profiles.Lock()
	Profiles.Items[macAddr] = p
	Profiles.Unlock()

	return p
}

// updateDeviceProfile can be used to update the profile for the passed identifiers.
func updateDeviceProfile(i *packetInfo) {
	// lookup profile
	Profiles.Lock()
	if p, ok := Profiles.Items[i.srcMAC]; ok {
		applyDeviceProfileUpdate(p, i)
	} else {
		Profiles.Items[i.srcMAC] = newDeviceProfile(i)
		profiles++
	}
	Profiles.Unlock()
}

// newDeviceProfile creates a new device specifc profile.
func newDeviceProfile(i *packetInfo) *deviceProfile {
	var contacts []*types.IPProfile
	if ip := getIPProfile(i.dstIP, i); ip != nil {
		contacts = append(contacts, ip.IPProfile)
	}
	var devices []*types.IPProfile
	if ip := getIPProfile(i.srcIP, i); ip != nil {
		devices = append(devices, ip.IPProfile)
	}

	return &deviceProfile{
		DeviceProfile: &types.DeviceProfile{
			MacAddr:            i.srcMAC,
			DeviceManufacturer: resolvers.LookupManufacturer(i.srcMAC),
			DeviceIPs:          devices,
			Contacts:           contacts,
			Timestamp:          i.timestamp,
			NumPackets:         1,
			Bytes:              uint64(len(i.p.Data())),
		},
	}
}

func applyDeviceProfileUpdate(p *deviceProfile, i *packetInfo) {
	p.Lock()

	// deviceIPs
	var found bool
	for _, pr := range p.DeviceIPs {
		if pr != nil {
			if pr.Addr == i.srcIP {
				// update existing ip profile
				pr = getIPProfile(i.srcIP, i).IPProfile
				found = true
			}
		}
	}
	// if no existing one has been updated, its a new one
	if !found {
		ip := getIPProfile(i.srcIP, i)
		// if the packet has no network layer we wont get an IP here
		// prevent adding a nil pointer to the array
		if ip != nil {
			p.DeviceIPs = append(p.DeviceIPs, ip.IPProfile)
		}
	}

	// contacts
	found = false
	for _, pr := range p.Contacts {
		if pr != nil {
			if pr.Addr == i.dstIP {
				// update existing ip profile
				pr = getIPProfile(i.dstIP, i).IPProfile
				found = true
			}
		}
	}
	// if no existing one has been updated, its a new one
	if !found {
		ip := getIPProfile(i.dstIP, i)

		// if the packet has no network layer we wont get an IP here
		// prevent adding a nil pointer to the array
		if ip != nil {
			p.Contacts = append(p.Contacts, ip.IPProfile)
		}
	}

	p.Bytes += uint64(len(i.p.Data()))
	p.NumPackets++
	p.Unlock()
}

var profileDecoder = newCustomDecoder(
	types.Type_NC_DeviceProfile,
	"DeviceProfile",
	"A DeviceProfile contains information about a single hardware device seen on the network and it's behavior",
	func(d *customDecoder) error {
		profileDecoderInstance = d

		return nil
	},
	func(p gopacket.Packet) proto.Message {
		// handle packet
		updateDeviceProfile(newPacketInfo(p))

		return nil
	},
	func(e *customDecoder) error {
		// teardown DPI C libs
		dpi.Destroy()

		// flush writer
		if !e.writer.IsChanWriter {
			for _, c := range Profiles.Items {
				c.Lock()
				writeProfile(c.DeviceProfile)
				c.Unlock()
			}
		}

		return nil
	},
)

// writeProfile writes the profile.
func writeProfile(d *types.DeviceProfile) {
	if c.Export {
		d.Inc()
	}

	atomic.AddInt64(&profileDecoderInstance.numRecords, 1)
	err := profileDecoderInstance.writer.Write(d)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
