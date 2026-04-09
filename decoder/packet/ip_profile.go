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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/internal/ja4"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

var (
	// LocalDNS controls whether the DNS names shall be resolved locally
	// without contacting a nameserver.
	LocalDNS = true
)

// atomicIPProfileMap contains all connections and provides synchronized access.
type atomicIPProfileMap struct {
	// SrcIP to DeviceProfiles
	Items map[string]*ipProfile
	sync.Mutex
}

// Size returns the number of elements in the Items map.
func (a *atomicIPProfileMap) Size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

// ipProfiles contains a map of IP specific behavior profiles at runtime.
var ipProfiles = &atomicIPProfileMap{
	Items: make(map[string]*ipProfile),
}

// ResetIPProfiles clears all IP profiles from memory
// This should be called when resetting state between processing different files
func ResetIPProfiles() {
	ipProfiles.Lock()
	ipProfiles.Items = make(map[string]*ipProfile)
	ipProfiles.Unlock()
}

// wrapper for the types.IPProfile that can be locked.
type ipProfile struct {
	sync.Mutex
	*types.IPProfile

	// buffer packets for deferred DPI analysis (keyed by stream)
	// Uses bufferedPacket to store copied data, avoiding gopacket buffer reuse issues
	streamPackets map[streamKey][]bufferedPacket
}

// updateIPProfile updates or creates an IP profile, buffering packets for deferred DPI
func updateIPProfile(ipAddr string, i *decoderutils.PacketInfo, source bool) {
	if ipAddr == "" {
		return
	}

	ipProfiles.Lock()
	p, exists := ipProfiles.Items[ipAddr]
	if !exists {
		// Create new IP profile
		p = createNewIPProfile(ipAddr, i, source)
		ipProfiles.Items[ipAddr] = p
		ipProfiles.Unlock()
		return
	}
	ipProfiles.Unlock()

	// Update existing profile
	p.Lock()
	defer p.Unlock()

	p.NumPackets++
	p.TimestampLast = i.Timestamp

	dataLen := uint64(len(i.Packet.Data()))
	p.Bytes += dataLen

	// Transport Layer: track ports
	if tl := i.Packet.TransportLayer(); tl != nil {
		if source {
			doSrcPortUpdate(p, utils.DecodePort(tl.TransportFlow().Src().Raw()), tl.LayerType().String(), dataLen)
			doContactedPortUpdate(p, utils.DecodePort(tl.TransportFlow().Dst().Raw()), tl.LayerType().String(), dataLen)
		} else {
			doDstPortUpdate(p, utils.DecodePort(tl.TransportFlow().Dst().Raw()), tl.LayerType().String(), dataLen)
			doContactedPortUpdate(p, utils.DecodePort(tl.TransportFlow().Src().Raw()), tl.LayerType().String(), dataLen)
		}
	}

	// Session Layer: TLS fingerprinting (lightweight, keep immediate)
	handleTLSFingerprinting(p, i)

	// Application Layer: DHCP fingerprinting (lightweight, keep immediate)
	handleDHCPFingerprinting(p, i)

	// Ensure streamPackets is initialized (defensive check)
	if p.streamPackets == nil {
		p.streamPackets = make(map[streamKey][]bufferedPacket)
	}

	// Buffer packet for deferred DPI analysis (up to 10 per stream)
	key := getStreamKey(i)
	if packets, exists := p.streamPackets[key]; exists {
		if len(packets) < maxPacketsPerStream {
			p.streamPackets[key] = append(packets, bufferedPacket{
				data:      copyPacketData(i.Packet),
				timestamp: i.Timestamp,
			})
		}
	} else {
		// Only create new stream buffer if under stream limit
		if len(p.streamPackets) < maxStreamsPerProfile {
			p.streamPackets[key] = []bufferedPacket{{
				data:      copyPacketData(i.Packet),
				timestamp: i.Timestamp,
			}}
		}
	}
}

// createNewIPProfile creates a new IP profile with initial packet data
func createNewIPProfile(ipAddr string, i *decoderutils.PacketInfo, source bool) *ipProfile {
	var (
		dataLen = uint64(len(i.Packet.Data()))
		sniMap  = make(map[string]int64)
	)

	// Network Layer: IP Geolocation
	loc, _ := resolvers.LookupGeolocation(ipAddr)

	// Transport Layer: Port information
	srcPorts, dstPorts, contactedPorts := initPorts(i, source)

	// Session Layer: TLS fingerprinting with JA4
	var ja4Fingerprints, ja4sFingerprints []string

	// JA4 Client Hello fingerprint
	ch := tlsx.GetClientHello(i.Packet)
	if ch != nil {
		if ch.SNI != "" {
			sniMap[ch.SNI] = 1
		}
		ja4CipherSuites := make([]uint16, len(ch.CipherSuites))
		for idx, cs := range ch.CipherSuites {
			ja4CipherSuites[idx] = uint16(cs)
		}
		ja4SignatureAlgs := make([]uint16, len(ch.SignatureAlgs))
		for idx, sa := range ch.SignatureAlgs {
			ja4SignatureAlgs[idx] = uint16(sa)
		}
		var supportedVers uint16
		for _, cs := range ch.CipherSuites {
			if uint16(cs) >= 0x1301 && uint16(cs) <= 0x1305 {
				supportedVers = 0x0304
				break
			}
		}
		ja4fp := ja4.ComputeJA4(&ja4.ClientHelloData{
			Version:             uint16(ch.Version),
			CipherSuites:        ja4CipherSuites,
			Extensions:          ch.AllExtensions,
			SNI:                 ch.SNI,
			ALPNs:               ch.ALPNs,
			SupportedVers:       supportedVers,
			IsQUIC:              false,
			SignatureAlgorithms: ja4SignatureAlgs,
		})
		ja4Fingerprints = append(ja4Fingerprints, ja4fp)
	}

	// JA4S Server Hello fingerprint
	sh := tlsx.GetServerHello(i.Packet)
	if sh != nil {
		ja4sExtensions := make([]uint16, len(sh.Extensions))
		for idx, ext := range sh.Extensions {
			ja4sExtensions[idx] = uint16(ext)
		}
		ja4sfp := ja4.ComputeJA4S(&ja4.ServerHelloData{
			Version:       uint16(sh.Vers),
			CipherSuite:   uint16(sh.CipherSuite),
			Extensions:    ja4sExtensions,
			SupportedVers: sh.SupportedVersion,
			IsQUIC:        false,
			ALPN:          sh.AlpnProtocol,
		})
		ja4sFingerprints = append(ja4sFingerprints, ja4sfp)
	}

	// Application Layer: DHCP fingerprinting
	var devices []string
	if dhcpFp := extractDHCPFingerprint(i.Packet); dhcpFp != "" {
		deviceName := resolvers.LookupDHCPFingerprintLocal(dhcpFp)
		if deviceName != "" {
			devices = append(devices, deviceName)
		}
	}

	var names []string
	if LocalDNS {
		if name := resolvers.LookupDNSNameLocal(ipAddr); len(name) != 0 {
			names = append(names, name)
		}
	} else {
		names = resolvers.LookupDNSNames(ipAddr)
	}

	// Initialize stream packet buffer with first packet (copy data to avoid buffer reuse)
	streamPackets := make(map[streamKey][]bufferedPacket)
	key := getStreamKey(i)
	streamPackets[key] = []bufferedPacket{{
		data:      copyPacketData(i.Packet),
		timestamp: i.Timestamp,
	}}

	return &ipProfile{
		IPProfile: &types.IPProfile{
			Addr:             ipAddr,
			NumPackets:       1,
			Geolocation:      loc,
			DNSNames:         names,
			TimestampFirst:   i.Timestamp,
			Protocols:        make(map[string]*types.Protocol), // Will be populated during flush
			Bytes:            dataLen,
			SrcPorts:         srcPorts,
			DstPorts:         dstPorts,
			ContactedPorts:   contactedPorts,
			SNIs:             sniMap,
			Ja4Fingerprints:  ja4Fingerprints,
			Ja4SFingerprints: ja4sFingerprints,
			Devices:          devices,
		},
		streamPackets: streamPackets,
	}
}

// handleTLSFingerprinting handles TLS fingerprinting for an IP profile
func handleTLSFingerprinting(p *ipProfile, i *decoderutils.PacketInfo) {
	// Handle JA4 (TLS Client Hello) fingerprinting
	ch := tlsx.GetClientHello(i.Packet)
	if ch != nil {
		if ch.SNI != "" {
			p.SNIs[ch.SNI]++
		}
		ja4CipherSuites := make([]uint16, len(ch.CipherSuites))
		for idx, cs := range ch.CipherSuites {
			ja4CipherSuites[idx] = uint16(cs)
		}
		ja4SignatureAlgs := make([]uint16, len(ch.SignatureAlgs))
		for idx, sa := range ch.SignatureAlgs {
			ja4SignatureAlgs[idx] = uint16(sa)
		}
		var supportedVers uint16
		for _, cs := range ch.CipherSuites {
			if uint16(cs) >= 0x1301 && uint16(cs) <= 0x1305 {
				supportedVers = 0x0304
				break
			}
		}
		ja4fp := ja4.ComputeJA4(&ja4.ClientHelloData{
			Version:             uint16(ch.Version),
			CipherSuites:        ja4CipherSuites,
			Extensions:          ch.AllExtensions,
			SNI:                 ch.SNI,
			ALPNs:               ch.ALPNs,
			SupportedVers:       supportedVers,
			IsQUIC:              false,
			SignatureAlgorithms: ja4SignatureAlgs,
		})
		p.Ja4Fingerprints = addUniqueString(p.Ja4Fingerprints, ja4fp)
	}

	// Handle JA4S (TLS Server Hello) fingerprinting
	sh := tlsx.GetServerHello(i.Packet)
	if sh != nil {
		ja4sExtensions := make([]uint16, len(sh.Extensions))
		for idx, ext := range sh.Extensions {
			ja4sExtensions[idx] = uint16(ext)
		}
		ja4sfp := ja4.ComputeJA4S(&ja4.ServerHelloData{
			Version:       uint16(sh.Vers),
			CipherSuite:   uint16(sh.CipherSuite),
			Extensions:    ja4sExtensions,
			SupportedVers: sh.SupportedVersion,
			IsQUIC:        false,
			ALPN:          sh.AlpnProtocol,
		})
		p.Ja4SFingerprints = addUniqueString(p.Ja4SFingerprints, ja4sfp)
	}
}

// handleDHCPFingerprinting handles DHCP fingerprinting for an IP profile
func handleDHCPFingerprinting(p *ipProfile, i *decoderutils.PacketInfo) {
	if dhcpFp := extractDHCPFingerprint(i.Packet); dhcpFp != "" {
		deviceName := resolvers.LookupDHCPFingerprintLocal(dhcpFp)
		if deviceName != "" {
			p.Devices = addUniqueString(p.Devices, deviceName)
		}
	}
}

// processIPProfileDeferredDPI runs DPI analysis on buffered packets during flush
func processIPProfileDeferredDPI(p *ipProfile) {
	if p.streamPackets == nil {
		return
	}

	// Process each stream's buffered packets
	for _, packets := range p.streamPackets {
		// Run DPI on each buffered packet in the stream
		for _, pkt := range packets {
			if len(pkt.data) == 0 {
				continue
			}
			// Decode the packet from raw bytes for DPI analysis
			// Use the detected base layer type from the pcap file
			packet := gopacket.NewPacket(pkt.data, baseLayerType, gopacket.Default)
			dpiResults := dpi.GetProtocols(packet)
			for protocol, res := range dpiResults {
				if prot, ok := p.Protocols[protocol]; ok {
					prot.Packets++
				} else {
					p.Protocols[protocol] = dpi.NewProto(&res)
				}
			}
		}
	}

	// Clear stream buffers after processing to free memory
	p.streamPackets = nil
}

// processIPProfileDeferredDPIWithoutClear runs DPI analysis but keeps the buffers for continued tracking
// This is used during live capture periodic flushing
func processIPProfileDeferredDPIWithoutClear(p *ipProfile) {
	if p.streamPackets == nil {
		return
	}

	// Process each stream's buffered packets
	for _, packets := range p.streamPackets {
		// Run DPI on each buffered packet in the stream
		for _, pkt := range packets {
			if len(pkt.data) == 0 {
				continue
			}
			// Decode the packet from raw bytes for DPI analysis
			// Use the detected base layer type from the pcap file
			packet := gopacket.NewPacket(pkt.data, baseLayerType, gopacket.Default)
			dpiResults := dpi.GetProtocols(packet)
			for protocol, res := range dpiResults {
				if prot, ok := p.Protocols[protocol]; ok {
					prot.Packets++
				} else {
					p.Protocols[protocol] = dpi.NewProto(&res)
				}
			}
		}
	}
	// Note: We do NOT clear stream buffers here to allow continued tracking
}

var ipProfileDecoder = newAccumulatingPacketDecoder(
	types.Type_NC_IPProfile,
	"IPProfile",
	"An IPProfile contains information about a single IPv4 or IPv6 address seen on the network and it's behavior",
	func(d *Decoder) error {
		return nil
	},
	func(p gopacket.Packet) proto.Message {
		// Buffer packets for both source and destination IPs
		info := decoderutils.NewPacketInfo(p)
		if info.SrcIP != "" {
			updateIPProfile(info.SrcIP, info, true)
		}
		if info.DstIP != "" {
			updateIPProfile(info.DstIP, info, false)
		}
		return nil
	},
	func(d *Decoder) error {
		// Take a snapshot of items under lock to avoid race conditions
		ipProfiles.Lock()
		items := make([]*ipProfile, 0, len(ipProfiles.Items))
		for _, item := range ipProfiles.Items {
			items = append(items, item)
		}
		ipProfiles.Unlock()

		// Process buffered packets and run deferred DPI analysis
		for _, item := range items {
			item.Lock()
			processIPProfileDeferredDPI(item)
			d.writeIPProfile(item.IPProfile)
			item.Unlock()
		}

		return nil
	},
	// FlushState: Write current state without clearing in-memory data
	func(d *Decoder) int64 {
		var numFlushed int64

		// Take a snapshot of items under lock to avoid race conditions
		ipProfiles.Lock()
		items := make([]*ipProfile, 0, len(ipProfiles.Items))
		for _, item := range ipProfiles.Items {
			items = append(items, item)
		}
		ipProfiles.Unlock()

		// Write current state of each profile without clearing
		for _, item := range items {
			item.Lock()
			// Process any buffered DPI data before writing (without clearing buffers)
			processIPProfileDeferredDPIWithoutClear(item)
			d.writeIPProfile(item.IPProfile)
			numFlushed++
			item.Unlock()
		}

		return numFlushed
	},
)

// getIPProfile is DEPRECATED. Replaced by updateIPProfile with deferred DPI for performance.
// This function performed immediate DPI analysis which was a major performance bottleneck.
// The new implementation buffers packets per stream and runs DPI during the flush phase.
func getIPProfile(ipAddr string, i *decoderutils.PacketInfo, source bool) *ipProfile {
	// This function is no longer used. Calls should use updateIPProfile instead.
	// Keeping this stub for backward compatibility during migration.
	return nil
}

func doSrcPortUpdate(p *ipProfile, srcPort int32, layerType string, dataLen uint64) {
	var found bool

	// source port
	for _, port := range p.SrcPorts {
		if port.PortNumber == srcPort && port.Protocol == layerType {

			atomic.AddUint64(&port.Stats.Bytes, dataLen)
			atomic.AddUint64(&port.Stats.Packets, 1)

			found = true

			break
		}
	}

	if !found {
		p.SrcPorts = append(p.SrcPorts, &types.Port{
			PortNumber: srcPort,
			Protocol:   layerType,
			Stats: &types.PortStats{
				Bytes:   dataLen,
				Packets: 1,
			},
		})
	}
}

func doContactedPortUpdate(p *ipProfile, dstPort int32, layerType string, dataLen uint64) {
	var found bool

	for _, port := range p.ContactedPorts {
		if port.PortNumber == dstPort && port.Protocol == layerType {

			atomic.AddUint64(&port.Stats.Bytes, dataLen)
			atomic.AddUint64(&port.Stats.Packets, 1)

			found = true

			break
		}
	}

	if !found {
		p.ContactedPorts = append(p.ContactedPorts, &types.Port{
			PortNumber: dstPort,
			Protocol:   layerType,
			Stats: &types.PortStats{
				Bytes:   dataLen,
				Packets: 1,
			},
		})
	}
}

func doDstPortUpdate(p *ipProfile, dstPort int32, layerType string, dataLen uint64) {
	var found bool

	// destination port
	for _, port := range p.DstPorts {
		if port.PortNumber == dstPort && port.Protocol == layerType {
			atomic.AddUint64(&port.Stats.Bytes, dataLen)
			atomic.AddUint64(&port.Stats.Packets, 1)

			found = true

			break
		}
	}

	if !found {
		p.DstPorts = append(p.DstPorts, &types.Port{
			PortNumber: dstPort,
			Protocol:   layerType,
			Stats: &types.PortStats{
				Bytes:   dataLen,
				Packets: 1,
			},
		})
	}
}

func initPorts(i *decoderutils.PacketInfo, source bool) (
	srcPorts,
	dstPorts,
	contactedPorts []*types.Port,
) {
	if tl := i.Packet.TransportLayer(); tl != nil {
		// get packet size
		dataLen := uint64(len(i.Packet.Data()))

		if source {
			// source port
			srcPorts = append(srcPorts, &types.Port{
				PortNumber: utils.DecodePort(tl.TransportFlow().Src().Raw()),
				Protocol:   tl.LayerType().String(),
				Stats: &types.PortStats{
					Bytes:   dataLen,
					Packets: 1,
				},
			})
			// contacted port
			contactedPorts = append(contactedPorts, &types.Port{
				PortNumber: utils.DecodePort(tl.TransportFlow().Dst().Raw()),
				Protocol:   tl.LayerType().String(),
				Stats: &types.PortStats{
					Bytes:   dataLen,
					Packets: 1,
				},
			})
		} else {
			// destination port
			dstPorts = append(dstPorts, &types.Port{
				PortNumber: utils.DecodePort(tl.TransportFlow().Dst().Raw()),
				Protocol:   tl.LayerType().String(),
				Stats: &types.PortStats{
					Bytes:   dataLen,
					Packets: 1,
				},
			})
			// contacted port
			contactedPorts = append(contactedPorts, &types.Port{
				PortNumber: utils.DecodePort(tl.TransportFlow().Src().Raw()),
				Protocol:   tl.LayerType().String(),
				Stats: &types.PortStats{
					Bytes:   dataLen,
					Packets: 1,
				},
			})
		}
	}

	return
}

// writeIPProfile writes the ip profile.
func (d *Decoder) writeIPProfile(i *types.IPProfile) {
	// Populate Applications field from Protocols map
	// This ensures the Applications field is correctly populated before writing
	if len(i.Protocols) > 0 {
		i.Applications = make([]string, 0, len(i.Protocols))
		for protocol := range i.Protocols {
			i.Applications = append(i.Applications, protocol)
		}
	}

	if conf.ExportMetrics {
		i.Inc()
	}

	atomic.AddInt64(&d.NumRecordsWritten, 1)

	err := d.Writer.Write(i)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}

// addUniqueString adds a string to a slice if it's not already present.
func addUniqueString(slice []string, item string) []string {
	if slices.Contains(slice, item) {
		return slice
	}
	return append(slice, item)
}

// extractDHCPFingerprint extracts the DHCP fingerprint from a packet.
// Returns the fingerprint as a comma-separated list of DHCP option types.
func extractDHCPFingerprint(p gopacket.Packet) string {
	// Try DHCPv4
	if dhcp4Layer := p.Layer(layers.LayerTypeDHCPv4); dhcp4Layer != nil {
		if dhcp4, ok := dhcp4Layer.(*layers.DHCPv4); ok {
			var fp strings.Builder
			length := len(dhcp4.Options) - 1
			for i, o := range dhcp4.Options {
				fp.WriteString(strconv.Itoa(int(o.Type)))
				if i != length {
					fp.WriteString(",")
				}
			}
			return fp.String()
		}
	}

	// Try DHCPv6
	if dhcp6Layer := p.Layer(layers.LayerTypeDHCPv6); dhcp6Layer != nil {
		if dhcp6, ok := dhcp6Layer.(*layers.DHCPv6); ok {
			var fp strings.Builder
			length := len(dhcp6.Options) - 1
			for i, o := range dhcp6.Options {
				fp.WriteString(strconv.Itoa(int(o.Code)))
				if i != length {
					fp.WriteString(",")
				}
			}
			return fp.String()
		}
	}

	return ""
}
