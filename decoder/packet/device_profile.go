/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package packet

import (
	"log"
	"slices"
	"sort"
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

// FindByIP returns the device profile that has the given IP in its DeviceIPs list.
// Returns nil if no match is found.
func (a *atomicDeviceProfileMap) FindByIP(ip string) *deviceProfile {
	a.Lock()
	defer a.Unlock()

	for _, dp := range a.Items {
		if slices.Contains(dp.DeviceIPs, ip) {
			return dp
		}
	}

	return nil
}

// EnrichFromDiscovery merges discovery data into the device profile.
func (dp *deviceProfile) EnrichFromDiscovery(hostnames, deviceTypes, roles []string, os string) {
	dp.Lock()
	defer dp.Unlock()

	for _, h := range hostnames {
		if !slices.Contains(dp.Hostnames, h) {
			dp.Hostnames = append(dp.Hostnames, h)
		}
	}
	for _, dt := range deviceTypes {
		if !slices.Contains(dp.DeviceTypes, dt) {
			dp.DeviceTypes = append(dp.DeviceTypes, dt)
		}
	}
	for _, r := range roles {
		if !slices.Contains(dp.Roles, r) {
			dp.Roles = append(dp.Roles, r)
		}
	}
	if os != "" && dp.OS == "" {
		dp.OS = os
	}
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
		found := slices.Contains(p.DeviceIPs, i.SrcIP)
		if !found {
			p.DeviceIPs = append(p.DeviceIPs, i.SrcIP)
		}
	}

	// Track contacts
	if i.DstIP != "" {
		found := slices.Contains(p.Contacts, i.DstIP)
		if !found {
			p.Contacts = append(p.Contacts, i.DstIP)
		}
	}

	p.Bytes += uint64(len(i.Packet.Data()))
	p.NumPackets++

	// Extract device discovery data from protocol layers
	enrichDeviceProfileFromPacket(p, i.Packet)

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

// FindByMAC returns the device profile for the given MAC address.
func (a *atomicDeviceProfileMap) FindByMAC(mac string) *deviceProfile {
	a.Lock()
	defer a.Unlock()

	return a.Items[mac]
}

// enrichDHCPDeviceProfile extracts hostname and vendor class from DHCP and applies to the correct device.
// If the Ethernet source is a DHCP relay (ClientHWAddr differs from profile MAC), the info is applied
// to the actual client's profile instead.
func enrichDHCPDeviceProfile(p *deviceProfile, dhcp4 *layers.DHCPv4) {
	var hostname, vendorClass string
	for _, o := range dhcp4.Options {
		switch o.Type {
		case layers.DHCPOptHostname:
			hostname = string(o.Data)
		case layers.DHCPOptClassID:
			vendorClass = string(o.Data)
		}
	}

	if hostname == "" && vendorClass == "" {
		return
	}

	// Check if this is a relayed DHCP packet
	clientMAC := dhcp4.ClientHWAddr.String()
	target := p
	if clientMAC != "" && clientMAC != p.MacAddr {
		if clientDP := DeviceProfiles.FindByMAC(clientMAC); clientDP != nil {
			target = clientDP
			target.Lock()
			defer target.Unlock()
		} else {
			return // client profile doesn't exist yet, don't pollute relay's profile
		}
	}

	if hostname != "" && !slices.Contains(target.Hostnames, hostname) {
		target.Hostnames = append(target.Hostnames, hostname)
	}
	if vendorClass != "" && target.OS == "" {
		target.OS = vendorClass
	}
}

// enrichDeviceProfileFromPacket extracts device information from DHCP, CDP, and LLDP layers.
// Called per-packet inside applyDeviceProfileUpdate (lock already held).
func enrichDeviceProfileFromPacket(p *deviceProfile, pkt gopacket.Packet) {
	// DHCP: extract hostname and vendor class (OS fingerprint)
	// Use ClientHWAddr to find the correct device profile — if the packet came from
	// a DHCP relay, the Ethernet source MAC is the relay, not the client.
	if dhcpLayer := pkt.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		if dhcp4, ok := dhcpLayer.(*layers.DHCPv4); ok {
			enrichDHCPDeviceProfile(p, dhcp4)
		}
	}

	// CDP: extract device name, platform, and software version
	if cdpLayer := pkt.Layer(layers.LayerTypeCiscoDiscovery); cdpLayer != nil {
		if cdp, ok := cdpLayer.(*layers.CiscoDiscovery); ok {
			for _, v := range cdp.Values {
				switch v.Type {
				case layers.CDPTLVDevID:
					deviceID := string(v.Value)
					if deviceID != "" && !slices.Contains(p.Hostnames, deviceID) {
						p.Hostnames = append(p.Hostnames, deviceID)
					}
				case layers.CDPTLVPlatform:
					platform := string(v.Value)
					if platform != "" && !slices.Contains(p.DeviceTypes, platform) {
						p.DeviceTypes = append(p.DeviceTypes, platform)
					}
				case layers.CDPTLVVersion:
					version := string(v.Value)
					if version != "" && p.OS == "" {
						// Truncate long IOS version strings
						if len(version) > 120 {
							version = version[:120]
						}
						p.OS = version
					}
				}
			}
		}
	}

	// LLDP: extract system name and system description from the Info layer
	if lldpInfoLayer := pkt.Layer(layers.LayerTypeLinkLayerDiscoveryInfo); lldpInfoLayer != nil {
		if lldpInfo, ok := lldpInfoLayer.(*layers.LinkLayerDiscoveryInfo); ok {
			sysName := string(lldpInfo.SysName)
			if sysName != "" && !slices.Contains(p.Hostnames, sysName) {
				p.Hostnames = append(p.Hostnames, sysName)
			}
			sysDesc := string(lldpInfo.SysDescription)
			if sysDesc != "" && p.OS == "" {
				if len(sysDesc) > 120 {
					sysDesc = sysDesc[:120]
				}
				p.OS = sysDesc
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
		macs := make([]string, 0, len(DeviceProfiles.Items))
		for mac := range DeviceProfiles.Items {
			macs = append(macs, mac)
		}
		// stable output order: Items is a map
		sort.Strings(macs)

		items := make([]*deviceProfile, 0, len(macs))
		for _, mac := range macs {
			items = append(items, DeviceProfiles.Items[mac])
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
		macs := make([]string, 0, len(DeviceProfiles.Items))
		for mac := range DeviceProfiles.Items {
			macs = append(macs, mac)
		}
		// stable output order: Items is a map
		sort.Strings(macs)

		items := make([]*deviceProfile, 0, len(macs))
		for _, mac := range macs {
			items = append(items, DeviceProfiles.Items[mac])
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
