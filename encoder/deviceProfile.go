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
	"log"
	"sync/atomic"

	"sync"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

// AtomicDeviceProfileMap contains all connections and provides synchronized access
type AtomicDeviceProfileMap struct {
	// SrcMAC to Profiles
	Items map[string]*types.DeviceProfile
	sync.Mutex
}

// Size returns the number of elements in the Items map
func (a *AtomicDeviceProfileMap) Size() int {
	a.Lock()
	defer a.Unlock()
	return len(a.Items)
}

var (
	// Profiles hold all connections
	Profiles = &AtomicDeviceProfileMap{
		Items: make(map[string]*types.DeviceProfile),
	}
	profileEncoderInstance *CustomEncoder
	profiles               int64

	// flags for flushing intervals - no flushing for now.
	//flagProfileFlushInterval = flag.Int("profile-flush-interval", 10000, "flush connections every X flows")

	//profileFlushInterval int64
	//profileTimeOut       time.Duration
)

// GetDeviceProfile fetches a known profile and updates it or returns a new one
func getDeviceProfile(macAddr string, i *idents) *types.DeviceProfile {

	if p, ok := Profiles.Items[macAddr]; ok {
		applyDeviceProfileUpdate(p, i)
		return p
	}

	// create new profile
	p := NewDeviceProfile(i)
	Profiles.Items[macAddr] = p

	return p
}

// UpdateDeviceProfile can be used to update the profile for the passed identifiers
func UpdateDeviceProfile(i *idents) {

	// lookup profile
	Profiles.Lock()
	if p, ok := Profiles.Items[i.srcMAC]; ok {
		applyDeviceProfileUpdate(p, i)
	} else {
		Profiles.Items[i.srcMAC] = NewDeviceProfile(i)
		profiles++
	}
	Profiles.Unlock()
}

// NewDeviceProfile creates a new device specifc profile
func NewDeviceProfile(i *idents) *types.DeviceProfile {
	var contacts []*types.IPProfile
	if ip := getIPProfile(i.dstIP, i); ip != nil {
		contacts = append(contacts, ip)
	}
	var devices []*types.IPProfile
	if ip := getIPProfile(i.srcIP, i); ip != nil {
		devices = append(devices, ip)
	}

	return &types.DeviceProfile{
		MacAddr:            i.srcMAC,
		DeviceManufacturer: resolvers.LookupManufacturer(i.srcMAC),
		DeviceIPs:          devices,
		Contacts:           contacts,
		Timestamp:          i.timestamp,
		NumPackets:         1,
		Bytes:              uint64(len(i.p.Data())),
	}
}

func applyDeviceProfileUpdate(p *types.DeviceProfile, i *idents) {

	// deviceIPs
	var found bool
	for _, pr := range p.DeviceIPs {
		if pr != nil {
			if pr.Addr == i.srcIP {
				// update existing ip profile
				pr = getIPProfile(i.srcIP, i)
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
			p.DeviceIPs = append(p.DeviceIPs, ip)
		}
	}

	// contacts
	found = false
	for _, pr := range p.Contacts {
		if pr != nil {
			if pr.Addr == i.dstIP {
				// update existing ip profile
				pr = getIPProfile(i.dstIP, i)
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
			p.Contacts = append(p.Contacts, ip)
		}
	}

	p.Bytes += uint64(len(i.p.Data()))
	p.NumPackets++
}

type idents struct {
	p         gopacket.Packet
	timestamp string
	srcMAC    string
	dstMAC    string
	srcIP     string
	dstIP     string
}

var profileEncoder = CreateCustomEncoder(types.Type_NC_DeviceProfile, "DeviceProfile", func(d *CustomEncoder) error {

	profileEncoderInstance = d

	return nil
}, func(p gopacket.Packet) proto.Message {

	// determine base info
	var i = new(idents)
	i.timestamp = p.Metadata().Timestamp.UTC().String()
	i.p = p
	if ll := p.LinkLayer(); ll != nil {
		i.srcMAC = ll.LinkFlow().Src().String()
		i.dstMAC = ll.LinkFlow().Dst().String()
	}
	if nl := p.NetworkLayer(); nl != nil {
		i.srcIP = nl.NetworkFlow().Src().String()
		i.dstIP = nl.NetworkFlow().Dst().String()
	}

	// handle packet
	UpdateDeviceProfile(i)

	return nil
}, func(e *CustomEncoder) error {

	// teardown DPI C libs
	dpi.Destroy()

	// flush writer
	if !e.writer.IsChanWriter {
		for _, c := range Profiles.Items {
			writeProfile(c)
		}
	}
	return nil
})

// writeProfile writes the profile
func writeProfile(c *types.DeviceProfile) {

	if profileEncoderInstance.export {
		c.Inc()
	}

	atomic.AddInt64(&profileEncoderInstance.numRecords, 1)
	err := profileEncoderInstance.writer.Write(c)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
