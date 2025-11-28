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

package injection

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/types"
)

// EngineConfig holds configuration for the injection engine.
type EngineConfig struct {
	// RulesPath is the path to rules file or directory.
	RulesPath string

	// QueueNum is the nfqueue number to use.
	QueueNum uint16

	// Interface is the network interface for packet injection.
	Interface string

	// AutoIPTables enables automatic iptables rule configuration.
	AutoIPTables bool

	// IPTablesTarget specifies the iptables target filter (e.g., "-d 192.168.1.0/24").
	IPTablesTarget string

	// Verbose enables verbose logging.
	Verbose bool

	// DryRun if true, evaluates rules but does not actually inject or modify packets.
	DryRun bool

	// LogActions if true, logs all injection actions to a file.
	LogActions bool

	// LogFile is the path to the action log file.
	LogFile string

	// MaxQueueLen is the maximum number of packets to queue.
	MaxQueueLen uint32

	// DefaultAction is the action to take when no rules match.
	DefaultAction Action
}

// DefaultEngineConfig returns a sane default configuration.
var DefaultEngineConfig = EngineConfig{
	QueueNum:      0,
	MaxQueueLen:   1024,
	DefaultAction: ActionAccept,
	Verbose:       false,
	DryRun:        false,
	LogActions:    true,
	LogFile:       "injection.log",
}

// InjectionContext provides access to packet data and metadata during rule evaluation.
type InjectionContext struct {
	// Packet is the decoded gopacket packet.
	Packet gopacket.Packet

	// RawData is the raw packet bytes.
	RawData []byte

	// Timestamp is when the packet was captured.
	Timestamp time.Time

	// Interface is the network interface the packet arrived on.
	Interface string

	// Direction indicates if packet is inbound or outbound.
	Direction PacketDirection

	// Ethernet layer (if present).
	Ethernet *layers.Ethernet

	// IPv4 layer (if present).
	IPv4 *layers.IPv4

	// IPv6 layer (if present).
	IPv6 *layers.IPv6

	// TCP layer (if present).
	TCP *layers.TCP

	// UDP layer (if present).
	UDP *layers.UDP

	// DNS layer (if present).
	DNS *layers.DNS

	// ARP layer (if present).
	ARP *layers.ARP

	// Payload is the application-layer payload.
	Payload []byte

	// AuditRecord is the decoded netcap audit record (if available).
	AuditRecord types.AuditRecord

	// Flow identifier string.
	Flow string

	// MatchedRules contains the names of rules that matched this packet.
	MatchedRules []string
}

// PacketDirection indicates packet flow direction.
type PacketDirection int

const (
	// DirectionUnknown when direction cannot be determined.
	DirectionUnknown PacketDirection = iota

	// DirectionInbound for packets coming into the system.
	DirectionInbound

	// DirectionOutbound for packets leaving the system.
	DirectionOutbound
)

// ActionResult represents the outcome of an injection action.
type ActionResult struct {
	// Action is the action that was executed.
	Action Action

	// Success indicates if the action completed successfully.
	Success bool

	// Error contains any error that occurred.
	Error error

	// ModifiedPacket is the modified packet data (for modify actions).
	ModifiedPacket []byte

	// InjectPackets are additional packets to inject.
	InjectPackets [][]byte

	// Drop indicates the original packet should be dropped.
	Drop bool

	// Delay specifies how long to delay the packet.
	Delay time.Duration

	// RuleName is the name of the rule that triggered this action.
	RuleName string

	// Timestamp is when the action was executed.
	Timestamp time.Time

	// Details contains action-specific details for logging.
	Details map[string]interface{}
}

// NewInjectionContext creates a new InjectionContext from a gopacket.Packet.
func NewInjectionContext(pkt gopacket.Packet, iface string) *InjectionContext {
	ctx := &InjectionContext{
		Packet:    pkt,
		RawData:   pkt.Data(),
		Timestamp: pkt.Metadata().Timestamp,
		Interface: iface,
	}

	// Extract layers
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		ctx.Ethernet = ethLayer.(*layers.Ethernet)
	}

	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ctx.IPv4 = ipv4Layer.(*layers.IPv4)
	}

	if ipv6Layer := pkt.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ctx.IPv6 = ipv6Layer.(*layers.IPv6)
	}

	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		ctx.TCP = tcpLayer.(*layers.TCP)
	}

	if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		ctx.UDP = udpLayer.(*layers.UDP)
	}

	if dnsLayer := pkt.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		ctx.DNS = dnsLayer.(*layers.DNS)
	}

	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		ctx.ARP = arpLayer.(*layers.ARP)
	}

	// Extract payload
	if appLayer := pkt.ApplicationLayer(); appLayer != nil {
		ctx.Payload = appLayer.Payload()
	}

	// Build flow identifier
	ctx.Flow = ctx.buildFlowID()

	return ctx
}

// buildFlowID creates a flow identifier string.
func (ctx *InjectionContext) buildFlowID() string {
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16

	if ctx.IPv4 != nil {
		srcIP = ctx.IPv4.SrcIP
		dstIP = ctx.IPv4.DstIP
	} else if ctx.IPv6 != nil {
		srcIP = ctx.IPv6.SrcIP
		dstIP = ctx.IPv6.DstIP
	}

	if ctx.TCP != nil {
		srcPort = uint16(ctx.TCP.SrcPort)
		dstPort = uint16(ctx.TCP.DstPort)
	} else if ctx.UDP != nil {
		srcPort = uint16(ctx.UDP.SrcPort)
		dstPort = uint16(ctx.UDP.DstPort)
	}

	if srcIP != nil && dstIP != nil {
		return fmt.Sprintf("%s:%d -> %s:%d", srcIP.String(), srcPort, dstIP.String(), dstPort)
	}

	return ""
}

// SrcIP returns the source IP address as a string.
func (ctx *InjectionContext) SrcIP() string {
	if ctx.IPv4 != nil {
		return ctx.IPv4.SrcIP.String()
	}
	if ctx.IPv6 != nil {
		return ctx.IPv6.SrcIP.String()
	}
	return ""
}

// DstIP returns the destination IP address as a string.
func (ctx *InjectionContext) DstIP() string {
	if ctx.IPv4 != nil {
		return ctx.IPv4.DstIP.String()
	}
	if ctx.IPv6 != nil {
		return ctx.IPv6.DstIP.String()
	}
	return ""
}

// SrcPort returns the source port.
func (ctx *InjectionContext) SrcPort() uint16 {
	if ctx.TCP != nil {
		return uint16(ctx.TCP.SrcPort)
	}
	if ctx.UDP != nil {
		return uint16(ctx.UDP.SrcPort)
	}
	return 0
}

// DstPort returns the destination port.
func (ctx *InjectionContext) DstPort() uint16 {
	if ctx.TCP != nil {
		return uint16(ctx.TCP.DstPort)
	}
	if ctx.UDP != nil {
		return uint16(ctx.UDP.DstPort)
	}
	return 0
}

// Protocol returns the transport protocol.
func (ctx *InjectionContext) Protocol() string {
	if ctx.TCP != nil {
		return "TCP"
	}
	if ctx.UDP != nil {
		return "UDP"
	}
	return ""
}

// HasTCP returns true if the packet has a TCP layer.
func (ctx *InjectionContext) HasTCP() bool {
	return ctx.TCP != nil
}

// HasUDP returns true if the packet has a UDP layer.
func (ctx *InjectionContext) HasUDP() bool {
	return ctx.UDP != nil
}

// HasDNS returns true if the packet has a DNS layer.
func (ctx *InjectionContext) HasDNS() bool {
	return ctx.DNS != nil
}

// HasARP returns true if the packet has an ARP layer.
func (ctx *InjectionContext) HasARP() bool {
	return ctx.ARP != nil
}
