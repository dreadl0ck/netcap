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
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"log"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type DeviceProfile struct {
	*types.DeviceProfile
	sync.Mutex
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicDeviceProfileMap struct {
	// SrcMAC to DeviceProfiles
	Items map[string]*DeviceProfile
	sync.Mutex
}

// Size returns the number of elements in the Items map.
func (a *atomicDeviceProfileMap) Size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

var (
	// DeviceProfiles hold all connections.
	DeviceProfiles = &atomicDeviceProfileMap{
		Items: make(map[string]*DeviceProfile),
	}
	deviceProfileDecoderInstance *PacketDecoder
	deviceProfiles               int64

	// flags for flushing intervals - no flushing for now.
	// flagProfileFlushInterval = flag.Int("profile-flush-interval", 10000, "flush connections every X flows").

	// profileFlushInterval int64
	// profileTimeOut       time.Duration.
)

// GetDeviceProfile fetches a known profile and updates it or returns a new one.
func GetDeviceProfile(macAddr string, i *decoderutils.PacketInfo) *DeviceProfile {
	DeviceProfiles.Lock()
	if p, ok := DeviceProfiles.Items[macAddr]; ok {
		DeviceProfiles.Unlock()
		applyDeviceProfileUpdate(p, i)
		return p
	}
	DeviceProfiles.Unlock()

	// create new profile
	p := newDeviceProfile(i)

	DeviceProfiles.Lock()
	DeviceProfiles.Items[macAddr] = p
	DeviceProfiles.Unlock()

	return p
}

// updateDeviceProfile can be used to update the profile for the passed identifiers.
func updateDeviceProfile(i *decoderutils.PacketInfo) {
	// lookup profile
	DeviceProfiles.Lock()
	if p, ok := DeviceProfiles.Items[i.SrcMAC]; ok {
		applyDeviceProfileUpdate(p, i)
	} else {
		DeviceProfiles.Items[i.SrcMAC] = newDeviceProfile(i)
		deviceProfiles++
	}
	DeviceProfiles.Unlock()
}

// newDeviceProfile creates a new device specific profile.
func newDeviceProfile(i *decoderutils.PacketInfo) *DeviceProfile {
	var contacts []string
	if ip := getIPProfile(i.DstIP, i, false); ip != nil {
		contacts = append(contacts, ip.IPProfile.Addr)
	}

	var devices []string
	if ip := getIPProfile(i.SrcIP, i, true); ip != nil {
		devices = append(devices, ip.IPProfile.Addr)
	}

	return &DeviceProfile{
		DeviceProfile: &types.DeviceProfile{
			MacAddr:            i.SrcMAC,
			DeviceManufacturer: resolvers.LookupManufacturer(i.SrcMAC),
			DeviceIPs:          devices,
			Contacts:           contacts,
			Timestamp:          i.Timestamp,
			NumPackets:         1,
			Bytes:              uint64(len(i.Packet.Data())),
		},
	}
}

func applyDeviceProfileUpdate(p *DeviceProfile, i *decoderutils.PacketInfo) {
	p.Lock()

	// deviceIPs
	var found bool

	for _, addr := range p.DeviceIPs {
		if addr == i.SrcIP {
			// update existing ip profile
			_ = getIPProfile(i.SrcIP, i, true).IPProfile
			found = true
		}
	}

	// if no existing one has been updated, its a new one
	if !found {
		ip := getIPProfile(i.SrcIP, i, true)
		// if the packet has no network layer we wont get an IP here
		// prevent adding a nil pointer to the array
		if ip != nil {
			p.DeviceIPs = append(p.DeviceIPs, ip.IPProfile.Addr)
		}
	}

	// contacts
	found = false

	for _, addr := range p.Contacts {
		if addr == i.DstIP {
			// update existing ip profile
			_ = getIPProfile(i.DstIP, i, false).IPProfile
			found = true
		}
	}

	// if no existing one has been updated, its a new one
	if !found {
		ip := getIPProfile(i.DstIP, i, false)

		// if the packet has no network layer we wont get an IP here
		// prevent adding a nil pointer to the array
		if ip != nil {
			p.Contacts = append(p.Contacts, ip.IPProfile.Addr)
		}
	}

	p.Bytes += uint64(len(i.Packet.Data()))
	p.NumPackets++
	p.Unlock()
}

var deviceProfileDecoder = NewPacketDecoder(
	types.Type_NC_DeviceProfile,
	"DeviceProfile",
	"A DeviceProfile contains information about a single hardware device seen on the network and it's behavior",
	func(d *PacketDecoder) error {
		deviceProfileDecoderInstance = d

		return nil
	},
	func(p gopacket.Packet) proto.Message {
		// handle packet
		updateDeviceProfile(decoderutils.NewPacketInfo(p))

		return nil
	},
	func(e *PacketDecoder) error {
		// flush writer
		for _, item := range DeviceProfiles.Items {
			item.Lock()
			writeDeviceProfile(item.DeviceProfile)
			item.Unlock()
		}

		return nil
	},
)

// writeDeviceProfile writes the profile.
func writeDeviceProfile(d *types.DeviceProfile) {
	if conf.ExportMetrics {
		d.Inc()
	}

	atomic.AddInt64(&deviceProfileDecoderInstance.NumRecordsWritten, 1)

	err := deviceProfileDecoderInstance.Writer.Write(d)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
