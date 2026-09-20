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
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/tlsx"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/dpi"
	"github.com/dreadl0ck/netcap/internal/ja4"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

// isPrivateIP checks if an IP address is RFC1918 private
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// RFC1918 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	private10 := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	private172 := net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}
	private192 := net.IPNet{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}

	return private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip)
}

// isBroadcastIP checks if an IP address is a broadcast address
func isBroadcastIP(ipStr string) bool {
	return ipStr == "255.255.255.255" || strings.HasSuffix(ipStr, ".255")
}

// isMulticastIP checks if an IP address is multicast
func isMulticastIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsMulticast()
}

// connectionID is a bidirectional connection
// between two devices over the network
// that includes the Link, Network and TransportLayer.
type connectionID struct {
	LinkFlowID      uint64
	NetworkFlowID   uint64
	TransportFlowID uint64
}

func (c connectionID) String() string {
	return strconv.FormatUint(c.LinkFlowID, 10) + strconv.FormatUint(c.NetworkFlowID, 10) + strconv.FormatUint(c.TransportFlowID, 10)
}

type connection struct {
	sync.Mutex
	*types.Connection
	clientIP string

	// to break the initialization loop when accessing the connectionDecoder variable within the connection processor
	// we simply set a reference to it when passing connections to the workers.
	decoder *Decoder

	// track unique applications detected via DPI
	applications map[string]struct{}

	// track packet counts per direction for behavioral analysis
	packetsClientToServer int64
	packetsServerToClient int64

	// JA4L timing fields (tracked at runtime, calculated at flush)
	synTimestamp         int64 // Timestamp when SYN was first seen
	synAckTimestamp      int64 // Timestamp when SYN-ACK was first seen
	synTTL               uint8 // TTL from the SYN packet
	clientHelloTimestamp int64 // Timestamp when TLS ClientHello was first seen
	serverHelloTimestamp int64 // Timestamp when TLS ServerHello was first seen

	// TLS SNI (Server Name Indication)
	sni string // SNI hostname from TLS ClientHello
}

// atomicConnMap contains all connections and provides synchronized access.
type atomicConnMap struct {
	sync.Mutex
	operations sync.RWMutex
	Items      map[string]*connection
}

// Size returns the number of elements in the Items map.
func (a *atomicConnMap) Size() int {
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

var conns = &atomicConnMap{
	Items: make(map[string]*connection),
}

// ResetConnections clears all connections from memory
// This should be called when resetting state between processing different files
func ResetConnections() {
	conns.operations.Lock()
	defer conns.operations.Unlock()
	conns.Lock()
	conns.Items = make(map[string]*connection)
	conns.Unlock()
}

var connectionDecoder = newAccumulatingPacketDecoder(
	types.Type_NC_Connection,
	"Connection",
	"A connection represents bi-directional network communication between two hosts based on the combined link-, network- and transport layer identifiers",
	nil,
	func(p gopacket.Packet) proto.Message {
		return handlePacket(p)
	},
	func(decoder *Decoder) error {
		conns.operations.Lock()
		defer conns.operations.Unlock()

		cp := connectionProcessor{}
		cp.initWorkers(decoderconfig.Instance.StreamBufferSize, decoderconfig.Instance.NumStreamWorkers)

		conns.Lock()
		cp.numTotal = len(conns.Items)

		// stable output order: Items is a map
		idents := make([]string, 0, len(conns.Items))
		for ident := range conns.Items {
			idents = append(idents, ident)
		}
		sort.Strings(idents)

		for _, ident := range idents {
			conn := conns.Items[ident]
			conn.decoder = decoder
			cp.handleConnection(conn)
		}
		conns.Unlock()
		cp.wg.Wait()

		// CRITICAL: Stop all workers by sending nil, then close channels
		for i, w := range cp.workers {
			w <- nil            // Signal worker to exit
			close(w)            // Close the channel
			cp.workers[i] = nil // Nil out reference to help GC
		}

		return nil
	},
	// FlushState: Write current state without clearing in-memory data
	func(decoder *Decoder) int64 {
		conns.operations.RLock()
		defer conns.operations.RUnlock()
		var numFlushed int64

		// Take a snapshot of items under lock to avoid race conditions
		conns.Lock()
		idents := make([]string, 0, len(conns.Items))
		for ident := range conns.Items {
			idents = append(idents, ident)
		}
		// stable output order: Items is a map
		sort.Strings(idents)

		items := make([]*connection, 0, len(idents))
		for _, ident := range idents {
			items = append(items, conns.Items[ident])
		}
		conns.Unlock()

		// Write current state of each connection without clearing
		for _, conn := range items {
			conn.Lock()
			// Write the connection record directly without going through the worker pool
			writeConnectionRecord(decoder, conn)
			numFlushed++
			conn.Unlock()
		}

		return numFlushed
	},
)

func handlePacket(p gopacket.Packet) proto.Message {
	// Reset and final flushing must wait for admitted updates to finish.
	conns.operations.RLock()
	defer conns.operations.RUnlock()

	// assemble connectionID
	connID := connectionID{}
	ll := p.LinkLayer()
	if ll != nil {
		connID.LinkFlowID = ll.LinkFlow().FastHash()
	}

	nl := p.NetworkLayer()
	if nl != nil {
		connID.NetworkFlowID = nl.NetworkFlow().FastHash()
	}

	tl := p.TransportLayer()
	if tl != nil {
		connID.TransportFlowID = tl.TransportFlow().FastHash()
	}

	// lookup connection
	key := connID.String()
	conns.Lock()

	if conn, ok := conns.Items[key]; ok {
		conns.Unlock()

		conn.Lock()

		// check if received packet from the same connection
		// was captured BEFORE the connections FIRST seen timestamp
		if p.Metadata().Timestamp.Before(time.Unix(0, conn.TimestampFirst).UTC()) {

			// rewrite timestamp
			conn.TimestampFirst = p.Metadata().Timestamp.UnixNano()

			// rewrite source and destination parameters
			// since the first packet decides about the connection direction
			if ll != nil {
				if len(ll.LinkFlow().Src().Raw()) > 0 {
					conn.SrcMAC = ll.LinkFlow().Src().String()
				}
				if len(ll.LinkFlow().Dst().Raw()) > 0 {
					conn.DstMAC = ll.LinkFlow().Dst().String()
				}
			}

			if nl != nil {
				if len(nl.NetworkFlow().Src().Raw()) > 0 {
					conn.SrcIP = nl.NetworkFlow().Src().String()
				}
				if len(nl.NetworkFlow().Dst().Raw()) > 0 {
					conn.DstIP = nl.NetworkFlow().Dst().String()
				}
			}

			if tl != nil {
				// TODO: change field type to int and use binary.LittleEndian.Uint16(...Src().Raw())
				// Check if the endpoint has valid data before converting to string
				if len(tl.TransportFlow().Src().Raw()) > 0 {
					conn.SrcPort = tl.TransportFlow().Src().String()
				}
				if len(tl.TransportFlow().Dst().Raw()) > 0 {
					conn.DstPort = tl.TransportFlow().Dst().String()
				}
			}
		}

		// track amount of transferred bytes (application layer payload)
		// Use transport layer payload to capture all app data, not just decoded application layers
		// ApplicationLayer() only returns decoded protocols (DNS, TLS, etc.), not raw HTTP/other data
		if tl != nil {
			conn.AppPayloadSize += int32(len(tl.LayerPayload()))
		}

		if nl != nil {
			if conn.clientIP == nl.NetworkFlow().Src().String() {
				conn.BytesClientToServer += int64(p.Metadata().Length)
				conn.packetsClientToServer++
			} else {
				conn.BytesServerToClient += int64(p.Metadata().Length)
				conn.packetsServerToClient++
			}
		}
		conn.NumPackets++
		trackTCPStats(conn.Connection, p)
		trackJA4LTiming(conn, p)
		conn.TotalSize += int32(p.Metadata().Length)

		// check if LAST timestamp was before the current packet
		if conn.TimestampLast < p.Metadata().Timestamp.UnixNano() {
			// current packet is newer
			// update last seen timestamp
			conn.TimestampLast = p.Metadata().Timestamp.UnixNano()

			// the duration will be calculated once the connection is written to the audit record writer
			// so there is no need to calculate it in real-time
		} // else: do nothing, timestamp is still the oldest one

		// DPI: detect applications
		dpiStart := time.Now()
		dpiResults := dpi.GetProtocols(p)
		if dpiResults != nil && conf.PerfTracker != nil {
			conf.PerfTracker.RecordDPI(time.Since(dpiStart))
		}
		for protocol := range dpiResults {
			if conn.applications == nil {
				conn.applications = make(map[string]struct{})
			}
			conn.applications[protocol] = struct{}{}
		}

		conn.Unlock()
	} else { // create a new Connection
		co := &types.Connection{}
		// Use Community ID v1 specification for standardized flow identification
		// Falls back to MD5 hash if Community ID cannot be computed (e.g., missing layers)
		if cid := CalcCommunityID(p); cid != "" {
			co.CommunityID = cid
		} else {
			co.CommunityID = calcMd5(connID.String())
		}
		co.TimestampFirst = p.Metadata().Timestamp.UnixNano()
		co.TimestampLast = p.Metadata().Timestamp.UnixNano()
		co.TotalSize = int32(p.Metadata().Length)
		co.NumPackets = 1
		trackTCPStats(co, p)

		if ll != nil {
			co.LinkProto = ll.LayerType().String()
			if len(ll.LinkFlow().Src().Raw()) > 0 {
				co.SrcMAC = ll.LinkFlow().Src().String()
			}
			if len(ll.LinkFlow().Dst().Raw()) > 0 {
				co.DstMAC = ll.LinkFlow().Dst().String()
			}
		}
		if nl != nil {
			co.NetworkProto = nl.LayerType().String()
			if len(nl.NetworkFlow().Src().Raw()) > 0 {
				co.SrcIP = nl.NetworkFlow().Src().String()
			}
			if len(nl.NetworkFlow().Dst().Raw()) > 0 {
				co.DstIP = nl.NetworkFlow().Dst().String()
			}
		}
		if tl != nil {
			co.TransportProto = tl.LayerType().String()
			// Check if the endpoint has valid data before converting to string
			if len(tl.TransportFlow().Src().Raw()) > 0 {
				co.SrcPort = tl.TransportFlow().Src().String()
			}
			if len(tl.TransportFlow().Dst().Raw()) > 0 {
				co.DstPort = tl.TransportFlow().Dst().String()
			}
		}
		if al := p.ApplicationLayer(); al != nil {
			co.ApplicationProto = al.LayerType().String()
		}
		// Use transport layer payload for app data size - captures all payload data
		// not just decoded application layers (like DNS, TLS)
		if tl != nil {
			co.AppPayloadSize = int32(len(tl.LayerPayload()))
		}

		// track amount of transferred bytes
		co.BytesClientToServer += int64(p.Metadata().Length)

		// DPI: detect applications
		apps := make(map[string]struct{})
		dpiResults := dpi.GetProtocols(p)
		for protocol := range dpiResults {
			apps[protocol] = struct{}{}
		}

		newConn := &connection{
			Connection:            co,
			clientIP:              co.SrcIP,
			applications:          apps,
			packetsClientToServer: 1, // First packet is from client
		}
		// Track JA4L timing for the first packet
		trackJA4LTiming(newConn, p)
		conns.Items[key] = newConn
		conns.Unlock()

		// TODO: add dedicated stats structure for decoder pkg
		// conns := atomic.AddInt64(&stream.stats.numConns, 1)

		// flush
		//if conf.ConnFlushInterval != 0 && conns%int64(conf.ConnFlushInterval) == 0 {
		//	cd.flushConns(p)
		//}
	}

	return nil
}

func trackTCPStats(co *types.Connection, p gopacket.Packet) {
	if t, ok := p.TransportLayer().(*layers.TCP); ok {
		if t.ACK {
			co.NumACKFlags++
		}
		if t.CWR {
			co.NumCWRFlags++
		}
		if t.ECE {
			co.NumECEFlags++
		}
		if t.FIN {
			co.NumFINFlags++
		}
		if t.RST {
			co.NumRSTFlags++
		}
		if t.NS {
			co.NumNSFlags++
		}
		if t.PSH {
			co.NumPSHFlags++
		}
		if t.URG {
			co.NumURGFlags++
		}
		if t.SYN {
			co.NumSYNFlags++
		}
		if co.MeanWindowSize == 0 {
			co.MeanWindowSize = int32(t.Window)
		} else {
			co.MeanWindowSize = movingAverage(co.MeanWindowSize, int32(t.Window), co.NumPackets)
		}
	}
}

func movingAverage(current int32, newValue int32, n int32) int32 {
	return (current + (newValue - current)) / n
}

// trackJA4LTiming tracks TCP handshake and TLS handshake timing for JA4L fingerprinting.
// This captures:
// - SYN timestamp and TTL for JA4L-C (TCP latency)
// - SYN-ACK timestamp for JA4L-C
// - ClientHello timestamp for JA4L-S (TLS latency)
// - ServerHello timestamp for JA4L-S
func trackJA4LTiming(conn *connection, p gopacket.Packet) {
	timestamp := p.Metadata().Timestamp.UnixNano()

	// Track TCP handshake timing (SYN / SYN-ACK)
	if tcp, ok := p.TransportLayer().(*layers.TCP); ok {
		// SYN packet (no ACK) - client initiating connection
		if tcp.SYN && !tcp.ACK && conn.synTimestamp == 0 {
			conn.synTimestamp = timestamp
			// Capture TTL from IP layer for hop count estimation
			if ipv4, ok := p.NetworkLayer().(*layers.IPv4); ok {
				conn.synTTL = ipv4.TTL
			} else if ipv6, ok := p.NetworkLayer().(*layers.IPv6); ok {
				conn.synTTL = ipv6.HopLimit
			}
		}

		// SYN-ACK packet - server responding
		if tcp.SYN && tcp.ACK && conn.synAckTimestamp == 0 {
			conn.synAckTimestamp = timestamp
		}
	}

	// Track TLS handshake timing (ClientHello / ServerHello) and extract SNI
	if conn.clientHelloTimestamp == 0 {
		if ch := tlsx.GetClientHello(p); ch != nil {
			conn.clientHelloTimestamp = timestamp
			// Extract SNI from TLS ClientHello if present
			if ch.SNI != "" && conn.sni == "" {
				conn.sni = ch.SNI
			}
		}
	}
	if conn.serverHelloTimestamp == 0 {
		if sh := tlsx.GetServerHello(p); sh != nil {
			conn.serverHelloTimestamp = timestamp
		}
	}
}

/*func flushConns(p gopacket.Packet) {
	selectConns := make([]*types.Connection, 0)

	for id, entry := range conns.Items {

		// flush entries whose last timestamp is connTimeOut older than current packet
		if p.Metadata().Timestamp.Sub(time.Unix(0, entry.TimestampLast)) > conf.ConnTimeOut {

			selectConns = append(selectConns, entry.Connection)

			// cleanup
			delete(conns.Items, id)
		}
	}

	// flush selection in background
	go func() {
		for _, selectedConn := range selectConns {
			writeConn(selectedConn)
		}
	}()
}*/

// writeConn writes the connection.
func (d *Decoder) writeConn(conn *types.Connection, clientIP string, apps map[string]struct{}, pktsC2S, pktsS2C int64, sni string) {

	// calculate duration
	conn.Duration = time.Unix(0, conn.TimestampLast).Sub(time.Unix(0, conn.TimestampFirst)).Nanoseconds()

	// Set SNI if detected from TLS ClientHello
	if sni != "" {
		conn.Sni = sni
	}

	// check if client IP for connection is still correct
	if clientIP != conn.SrcIP {

		// update client address
		clientIP = conn.SrcIP

		// swap num bytes tracked
		conn.BytesClientToServer, conn.BytesServerToClient = conn.BytesServerToClient, conn.BytesClientToServer
		// swap packet counts too
		pktsC2S, pktsS2C = pktsS2C, pktsC2S
	}

	// Populate behavioral analysis fields
	conn.PacketsClientToServer = pktsC2S
	conn.PacketsServerToClient = pktsS2C

	// Calculate byte ratio (client/server) - indicator for beaconing if very consistent
	if conn.BytesServerToClient > 0 {
		conn.ByteRatio = float64(conn.BytesClientToServer) / float64(conn.BytesServerToClient)
	}

	// Calculate packet ratio
	if pktsS2C > 0 {
		conn.PacketRatio = float64(pktsC2S) / float64(pktsS2C)
	}

	// Calculate average packet sizes
	if pktsC2S > 0 {
		conn.AvgPacketSizeClientToServer = int32(conn.BytesClientToServer / pktsC2S)
	}
	if pktsS2C > 0 {
		conn.AvgPacketSizeServerToClient = int32(conn.BytesServerToClient / pktsS2C)
	}

	// Check if connection is external (either IP is not RFC1918 private)
	conn.IsExternal = !isPrivateIP(conn.SrcIP) || !isPrivateIP(conn.DstIP)

	// Check for broadcast/multicast
	conn.IsBroadcast = isBroadcastIP(conn.DstIP)
	conn.IsMulticast = isMulticastIP(conn.DstIP)

	// populate Applications from DPI results
	if len(apps) > 0 {
		conn.Applications = make([]string, 0, len(apps))
		for app := range apps {
			conn.Applications = append(conn.Applications, app)
		}
		// DetectedProtocolName is derived from the first entry below, so the
		// map order would otherwise decide which protocol gets reported.
		sort.Strings(conn.Applications)
	}

	// Lookup service name for the destination (server) port
	if conn.DstPort != "" {
		if dstPort, err := strconv.Atoi(conn.DstPort); err == nil {
			// Use the transport protocol for lookup
			protocol := ""
			if conn.TransportProto == "TCP" {
				protocol = "TCP"
			} else if conn.TransportProto == "UDP" {
				protocol = "UDP"
			}

			if protocol != "" {
				conn.ServerPortName = resolvers.LookupServiceByPort(dstPort, protocol)
			}
		}
	}

	// GeoIP enrichment: attach country/ASN directly to the connection so
	// geographic-anomaly rules (e.g. S7comm from an unexpected country) can run
	// on Connection records. LookupGeolocation self-gates and returns empty
	// strings when the resolver is disabled or the address is unresolvable, so
	// this is a no-op in that case. Only public addresses are looked up.
	if conn.SrcIP != "" && !isPrivateIP(conn.SrcIP) {
		conn.SrcGeoLocation, conn.SrcASN = resolvers.LookupGeolocation(conn.SrcIP)
	}
	if conn.DstIP != "" && !isPrivateIP(conn.DstIP) {
		conn.DstGeoLocation, conn.DstASN = resolvers.LookupGeolocation(conn.DstIP)
	}

	// Set detected protocol name from DPI or transport protocol
	if len(conn.Applications) > 0 {
		// Use the first DPI-detected application as the protocol name
		conn.DetectedProtocolName = conn.Applications[0]
	} else if conn.ApplicationProto != "" && conn.ApplicationProto != "Payload" && conn.ApplicationProto != "DecodeFailure" {
		// Fallback to application layer protocol if available and meaningful
		conn.DetectedProtocolName = conn.ApplicationProto
	} else if conn.ServerPortName != "" {
		// Fallback to the service name if we have one
		conn.DetectedProtocolName = conn.ServerPortName
	}

	if conf.ExportMetrics {
		conn.Inc()
	}

	atomic.AddInt64(&d.NumRecordsWritten, 1)

	err := d.Writer.Write(conn)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}

// internal data structure to parallelize processing of Connection audit records
// when the core engine is stopped and the stored connections are processed.
type connectionProcessor struct {
	sync.Mutex
	workers    []chan *connection
	numWorkers int
	next       int
	wg         sync.WaitGroup
	numDone    int
	numTotal   int
	bufferSize int
}

// to process the streams in parallel
// they are passed to several worker goroutines in round robin style.
func (cp *connectionProcessor) handleConnection(conn *connection) {
	cp.wg.Add(1)

	// send the packetInfo to the decoder routine
	cp.workers[cp.next] <- conn

	// increment or reset next
	if cp.numWorkers == cp.next+1 {
		// reset
		cp.next = 0
	} else {
		cp.next++
	}
}

// worker spawns a new worker goroutine
// and returns a channel for receiving input connections.
// the wait group has already been incremented for each non-nil connection,
// so wg.Done() must be called before returning for each item.
func (cp *connectionProcessor) connectionWorker(wg *sync.WaitGroup) chan *connection {

	// init channel to receive input connections
	chanInput := make(chan *connection, cp.bufferSize)

	// start worker
	go func() {
		for conn := range chanInput {
			// nil conn is used to exit the loop,
			// the processing logic will never send a streamReader in here that is nil
			if conn == nil {
				return
			}

			// Calculate JA4L fingerprints before writing
			calculateJA4L(conn)
			conn.decoder.writeConn(conn.Connection, conn.clientIP, conn.applications, conn.packetsClientToServer, conn.packetsServerToClient, conn.sni)

			cp.Lock()
			cp.numDone++

			if !decoderconfig.Instance.Quiet {
				utils.ClearLine()
				fmt.Print("processing remaining Connection audit records... ", "(", cp.numDone, "/", cp.numTotal, ")")
			}

			cp.Unlock()
			wg.Done()
		}
	}()

	// return input channel
	return chanInput
}

// spawn the configured number of workers.
func (cp *connectionProcessor) initWorkers(bufferSize int, numStreamWorkers int) {
	cp.bufferSize = bufferSize
	cp.workers = make([]chan *connection, numStreamWorkers)

	for i := range cp.workers {
		cp.workers[i] = cp.connectionWorker(&cp.wg)
	}

	cp.numWorkers = len(cp.workers)
}

// writeConnectionRecord writes a connection record during periodic flushing.
// This is a simpler version that doesn't use workers since we're flushing
// existing state, not processing new packets.
func writeConnectionRecord(decoder *Decoder, conn *connection) {
	// Calculate JA4L fingerprints before writing
	calculateJA4L(conn)
	decoder.writeConn(conn.Connection, conn.clientIP, conn.applications, conn.packetsClientToServer, conn.packetsServerToClient, conn.sni)
}

// calculateJA4L calculates and populates JA4L fingerprint fields on the connection.
// JA4L-C: TCP latency (SYN → SYN-ACK)
// JA4L-S: TLS latency (ClientHello → ServerHello)
func calculateJA4L(conn *connection) {
	// Populate timing timestamps
	conn.Connection.SynTimestamp = conn.synTimestamp
	conn.Connection.SynAckTimestamp = conn.synAckTimestamp
	conn.Connection.ClientHelloTimestamp = conn.clientHelloTimestamp
	conn.Connection.ServerHelloTimestamp = conn.serverHelloTimestamp
	conn.Connection.SynTtl = int32(conn.synTTL)

	// Calculate JA4L-C (TCP RTT: SYN → SYN-ACK)
	if conn.synTimestamp > 0 && conn.synAckTimestamp > 0 {
		conn.Connection.TcpRttNanos = conn.synAckTimestamp - conn.synTimestamp
		conn.Connection.Ja4LClient = ja4.ComputeJA4L(conn.Connection.TcpRttNanos, conn.synTTL)
	}

	// Calculate JA4L-S (TLS latency: ClientHello → ServerHello)
	if conn.clientHelloTimestamp > 0 && conn.serverHelloTimestamp > 0 {
		conn.Connection.TlsHandshakeNanos = conn.serverHelloTimestamp - conn.clientHelloTimestamp
		conn.Connection.Ja4LServer = ja4.ComputeJA4L(conn.Connection.TlsHandshakeNanos, conn.synTTL)
	}
}
