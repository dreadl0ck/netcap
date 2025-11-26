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

package packet

import (
	"log"
	"sync"
	"sync/atomic"

	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

// streamKey uniquely identifies a network stream
type streamKey struct {
	srcIP    string
	dstIP    string
	srcPort  string
	dstPort  string
	protocol string
}

// bufferedPacket holds a copy of packet data for deferred DPI analysis
// We store raw bytes to avoid gopacket buffer reuse issues
type bufferedPacket struct {
	data      []byte
	timestamp int64
}

// streamBuffer holds buffered packets for a stream
type streamBuffer struct {
	packets []bufferedPacket
}

const (
	maxPacketsPerStream  = 10
	maxStreamsPerProfile = 1000 // Limit total streams to prevent unbounded growth
)

// baseLayerType stores the detected link layer type from the pcap file
// This is set by the collector when opening the file and used for decoding buffered packets
var baseLayerType = layers.LayerTypeEthernet // default to Ethernet

// SetBaseLayerType sets the base layer type for packet decoding
// This should be called by the collector when it determines the link type
func SetBaseLayerType(lt gopacket.LayerType) {
	baseLayerType = lt
}

// GetBaseLayerType returns the current base layer type
func GetBaseLayerType() gopacket.LayerType {
	return baseLayerType
}

// deviceProfile describes the behavior of a hardware device.
// This is a wrapper structure to allow safe atomic access.
type deviceProfile struct {
	sync.Mutex
	*types.DeviceProfile

	// track unique applications detected via DPI
	applications map[string]struct{}

	// buffer packets per stream for deferred DPI analysis
	streamBuffers map[streamKey]*streamBuffer
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicDeviceProfileMap struct {
	sync.Mutex
	// SrcMAC to deviceProfiles
	Items map[string]*deviceProfile
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
		Items: make(map[string]*deviceProfile),
	}
	deviceProfiles int64

	// flags for flushing intervals - no flushing for now.
	// flagProfileFlushInterval = flag.Int("profile-flush-interval", 10000, "flush connections every X flows").

	// profileFlushInterval int64
	// profileTimeOut       time.Duration.
)

// ResetDeviceProfiles clears all device profiles from memory
// This should be called when resetting state between processing different files
func ResetDeviceProfiles() {
	DeviceProfiles.Lock()
	DeviceProfiles.Items = make(map[string]*deviceProfile)
	DeviceProfiles.Unlock()
	atomic.StoreInt64(&deviceProfiles, 0)
}

// getDeviceProfile fetches a known profile and updates it or returns a new one.
//func getDeviceProfile(macAddr string, i *decoderutils.PacketInfo) *deviceProfile {
//	DeviceProfiles.Lock()
//	if p, ok := DeviceProfiles.Items[macAddr]; ok {
//		DeviceProfiles.Unlock()
//		applyDeviceProfileUpdate(p, i)
//		return p
//	}
//	DeviceProfiles.Unlock()
//
//	// create new profile
//	p := newDeviceProfile(i)
//
//	DeviceProfiles.Lock()
//	DeviceProfiles.Items[macAddr] = p
//	DeviceProfiles.Unlock()
//
//	return p
//}

// getStreamKey generates a unique key for a network stream
func getStreamKey(i *decoderutils.PacketInfo) streamKey {
	var srcPort, dstPort, protocol string

	if tl := i.Packet.TransportLayer(); tl != nil {
		// Check if the endpoint has valid data before converting to string
		// Some protocols may have transport layers without valid port data
		if len(tl.TransportFlow().Src().Raw()) > 0 {
			srcPort = tl.TransportFlow().Src().String()
		}
		if len(tl.TransportFlow().Dst().Raw()) > 0 {
			dstPort = tl.TransportFlow().Dst().String()
		}
		protocol = tl.LayerType().String()
	}

	return streamKey{
		srcIP:    i.SrcIP,
		dstIP:    i.DstIP,
		srcPort:  srcPort,
		dstPort:  dstPort,
		protocol: protocol,
	}
}

// updateDeviceProfile can be used to update the profile for the passed identifiers.
func updateDeviceProfile(i *decoderutils.PacketInfo) {
	// lookup profile
	DeviceProfiles.Lock()
	if p, ok := DeviceProfiles.Items[i.SrcMAC]; ok {
		DeviceProfiles.Unlock()
		applyDeviceProfileUpdate(p, i)
	} else {
		DeviceProfiles.Items[i.SrcMAC] = newDeviceProfile(i)
		deviceProfiles++
		DeviceProfiles.Unlock()
	}
}

// copyPacketData creates a copy of packet data to avoid gopacket buffer reuse issues
func copyPacketData(p gopacket.Packet) []byte {
	data := p.Data()
	if len(data) == 0 {
		return nil
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	return copied
}

// newDeviceProfile creates a new device specific profile.
func newDeviceProfile(i *decoderutils.PacketInfo) *deviceProfile {
	var contacts []string
	if i.DstIP != "" {
		contacts = append(contacts, i.DstIP)
	}

	var devices []string
	if i.SrcIP != "" {
		devices = append(devices, i.SrcIP)
	}

	// Initialize stream buffers and buffer the first packet (copy data to avoid buffer reuse)
	streamBuffers := make(map[streamKey]*streamBuffer)
	key := getStreamKey(i)
	streamBuffers[key] = &streamBuffer{
		packets: []bufferedPacket{{
			data:      copyPacketData(i.Packet),
			timestamp: i.Timestamp,
		}},
	}

	return &deviceProfile{
		DeviceProfile: &types.DeviceProfile{
			MacAddr:            i.SrcMAC,
			DeviceManufacturer: resolvers.LookupManufacturer(i.SrcMAC),
			DeviceIPs:          devices,
			Contacts:           contacts,
			Timestamp:          i.Timestamp,
			NumPackets:         1,
			Bytes:              uint64(len(i.Packet.Data())),
		},
		applications:  make(map[string]struct{}),
		streamBuffers: streamBuffers,
	}
}

func applyDeviceProfileUpdate(p *deviceProfile, i *decoderutils.PacketInfo) {
	p.Lock()
	defer p.Unlock()

	// Track deviceIPs
	if i.SrcIP != "" {
		found := false
		for _, addr := range p.DeviceIPs {
			if addr == i.SrcIP {
				found = true
				break
			}
		}
		if !found {
			p.DeviceIPs = append(p.DeviceIPs, i.SrcIP)
		}
	}

	// Track contacts
	if i.DstIP != "" {
		found := false
		for _, addr := range p.Contacts {
			if addr == i.DstIP {
				found = true
				break
			}
		}
		if !found {
			p.Contacts = append(p.Contacts, i.DstIP)
		}
	}

	p.Bytes += uint64(len(i.Packet.Data()))
	p.NumPackets++

	// Ensure streamBuffers is initialized (defensive check)
	if p.streamBuffers == nil {
		p.streamBuffers = make(map[streamKey]*streamBuffer)
	}

	// Buffer packet for deferred DPI analysis (up to 10 packets per stream)
	key := getStreamKey(i)
	if buf, exists := p.streamBuffers[key]; exists {
		// Stream already exists, add packet if under limit
		if len(buf.packets) < maxPacketsPerStream {
			buf.packets = append(buf.packets, bufferedPacket{
				data:      copyPacketData(i.Packet),
				timestamp: i.Timestamp,
			})
		}
	} else {
		// New stream, create buffer only if under stream limit
		if len(p.streamBuffers) < maxStreamsPerProfile {
			p.streamBuffers[key] = &streamBuffer{
				packets: []bufferedPacket{{
					data:      copyPacketData(i.Packet),
					timestamp: i.Timestamp,
				}},
			}
		}
	}
}

var deviceProfileDecoder = newAccumulatingPacketDecoder(
	types.Type_NC_DeviceProfile,
	"DeviceProfile",
	"A DeviceProfile contains information about a single hardware device seen on the network and it's behavior",
	func(d *Decoder) error {
		return nil
	},
	func(p gopacket.Packet) proto.Message {
		// handle packet
		updateDeviceProfile(decoderutils.NewPacketInfo(p))

		return nil
	},
	func(d *Decoder) error {
		// Take a snapshot of items under lock to avoid race conditions
		DeviceProfiles.Lock()
		items := make([]*deviceProfile, 0, len(DeviceProfiles.Items))
		for _, item := range DeviceProfiles.Items {
			items = append(items, item)
		}
		DeviceProfiles.Unlock()

		// Process buffered packets and run DPI analysis before flushing
		for _, item := range items {
			item.Lock()
			processDeferredDPI(item)
			d.writeDeviceProfile(item.DeviceProfile, item.applications)
			item.Unlock()
		}

		return nil
	},
	// FlushState: Write current state without clearing in-memory data
	func(d *Decoder) int64 {
		var numFlushed int64

		// Take a snapshot of items under lock to avoid race conditions
		DeviceProfiles.Lock()
		items := make([]*deviceProfile, 0, len(DeviceProfiles.Items))
		for _, item := range DeviceProfiles.Items {
			items = append(items, item)
		}
		DeviceProfiles.Unlock()

		// Write current state of each profile without clearing
		for _, item := range items {
			item.Lock()
			// Process any buffered DPI data before writing
			processDeferredDPIWithoutClear(item)
			d.writeDeviceProfile(item.DeviceProfile, item.applications)
			numFlushed++
			item.Unlock()
		}

		return numFlushed
	},
)

// processDeferredDPI runs DPI analysis on all buffered packets for a device profile
func processDeferredDPI(p *deviceProfile) {
	if p.streamBuffers == nil {
		return
	}

	// Process each stream's buffered packets
	for _, streamBuf := range p.streamBuffers {
		// Run DPI on each buffered packet in the stream
		for _, pkt := range streamBuf.packets {
			if len(pkt.data) == 0 {
				continue
			}
			// Decode the packet from raw bytes for DPI analysis
			// Use the detected base layer type from the pcap file
			packet := gopacket.NewPacket(pkt.data, baseLayerType, gopacket.Default)
			dpiResults := dpi.GetProtocols(packet)
			for protocol := range dpiResults {
				p.applications[protocol] = struct{}{}
			}
		}
	}

	// Clear stream buffers after processing to free memory
	p.streamBuffers = nil
}

// processDeferredDPIWithoutClear runs DPI analysis but keeps the buffers for continued tracking
// This is used during live capture periodic flushing
func processDeferredDPIWithoutClear(p *deviceProfile) {
	if p.streamBuffers == nil {
		return
	}

	// Process each stream's buffered packets
	for _, streamBuf := range p.streamBuffers {
		// Run DPI on each buffered packet in the stream
		for _, pkt := range streamBuf.packets {
			if len(pkt.data) == 0 {
				continue
			}
			// Decode the packet from raw bytes for DPI analysis
			// Use the detected base layer type from the pcap file
			packet := gopacket.NewPacket(pkt.data, baseLayerType, gopacket.Default)
			dpiResults := dpi.GetProtocols(packet)
			for protocol := range dpiResults {
				p.applications[protocol] = struct{}{}
			}
		}
	}
	// Note: We do NOT clear stream buffers here to allow continued tracking
}

// writeDeviceProfile writes the profile.
func (d *Decoder) writeDeviceProfile(dp *types.DeviceProfile, apps map[string]struct{}) {
	// populate Applications from DPI results
	if len(apps) > 0 {
		dp.Applications = make([]string, 0, len(apps))
		for app := range apps {
			dp.Applications = append(dp.Applications, app)
		}
	}

	if conf.ExportMetrics {
		dp.Inc()
	}

	atomic.AddInt64(&d.NumRecordsWritten, 1)

	err := d.Writer.Write(dp)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
