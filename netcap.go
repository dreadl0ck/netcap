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

package netcap

import (
	"io"

	"github.com/dreadl0ck/netcap/types"
	proto "github.com/golang/protobuf/proto"
)

// Version is the current version of the netcap library
const Version = "v0.3.6"

// InitRecord initializes a new record of the given type
// that conforms to the proto.Message interface
// if netcap is extended with new audit records they need to be added here as well
func InitRecord(typ types.Type) (record proto.Message) {

	switch typ {
	case types.Type_NC_IPv4:
		record = new(types.IPv4)
	case types.Type_NC_IPv6:
		record = new(types.IPv6)
	case types.Type_NC_IPv6Fragment:
		record = new(types.IPv6Fragment)
	case types.Type_NC_DNS:
		record = new(types.DNS)
	case types.Type_NC_UDP:
		record = new(types.UDP)
	case types.Type_NC_TCP:
		record = new(types.TCP)
	case types.Type_NC_DHCPv4:
		record = new(types.DHCPv4)
	case types.Type_NC_DHCPv6:
		record = new(types.DHCPv6)
	case types.Type_NC_ICMPv4:
		record = new(types.ICMPv4)
	case types.Type_NC_ICMPv6:
		record = new(types.ICMPv6)
	case types.Type_NC_ICMPv6Echo:
		record = new(types.ICMPv6Echo)
	case types.Type_NC_ARP:
		record = new(types.ARP)
	case types.Type_NC_Ethernet:
		record = new(types.Ethernet)
	case types.Type_NC_SIP:
		record = new(types.SIP)
	case types.Type_NC_LLC:
		record = new(types.LLC)
	case types.Type_NC_IGMP:
		record = new(types.IGMP)
	case types.Type_NC_IPv6HopByHop:
		record = new(types.IPv6HopByHop)
	case types.Type_NC_NTP:
		record = new(types.NTP)
	case types.Type_NC_SCTP:
		record = new(types.SCTP)
	case types.Type_NC_ICMPv6RouterAdvertisement:
		record = new(types.ICMPv6RouterAdvertisement)
	case types.Type_NC_ICMPv6RouterSolicitation:
		record = new(types.ICMPv6RouterSolicitation)
	case types.Type_NC_ICMPv6NeighborAdvertisement:
		record = new(types.ICMPv6NeighborAdvertisement)
	case types.Type_NC_ICMPv6NeighborSolicitation:
		record = new(types.ICMPv6NeighborSolicitation)
	case types.Type_NC_LinkLayerDiscovery:
		record = new(types.LinkLayerDiscovery)
	case types.Type_NC_SNAP:
		record = new(types.SNAP)
	case types.Type_NC_EthernetCTP:
		record = new(types.EthernetCTP)
	case types.Type_NC_EthernetCTPReply:
		record = new(types.EthernetCTPReply)
	case types.Type_NC_LinkLayerDiscoveryInfo:
		record = new(types.LinkLayerDiscoveryInfo)
	case types.Type_NC_Dot11:
		record = new(types.Dot11)
	case types.Type_NC_Dot1Q:
		record = new(types.Dot1Q)
	case types.Type_NC_HTTP:
		record = new(types.HTTP)
	case types.Type_NC_TLSClientHello:
		record = new(types.TLSClientHello)
	case types.Type_NC_Connection:
		record = new(types.Connection)
	case types.Type_NC_Flow:
		record = new(types.Flow)
	case types.Type_NC_LinkFlow:
		record = new(types.LinkFlow)
	case types.Type_NC_NetworkFlow:
		record = new(types.NetworkFlow)
	case types.Type_NC_TransportFlow:
		record = new(types.TransportFlow)
	case types.Type_NC_IPSecAH:
		record = new(types.IPSecAH)
	case types.Type_NC_IPSecESP:
		record = new(types.IPSecESP)
	case types.Type_NC_Geneve:
		record = new(types.Geneve)
	case types.Type_NC_VXLAN:
		record = new(types.VXLAN)
	case types.Type_NC_USB:
		record = new(types.USB)
	case types.Type_NC_LCM:
		record = new(types.LCM)
	case types.Type_NC_MPLS:
		record = new(types.MPLS)
	case types.Type_NC_ModbusTCP:
		record = new(types.ModbusTCP)
	case types.Type_NC_OSPFv2:
		record = new(types.OSPFv2)
	case types.Type_NC_OSPFv3:
		record = new(types.OSPFv3)
	default:
		panic("InitRecord: unknown type: " + typ.String())
	}
	return record
}

// Count returns the total number of records found in an audit record file
func Count(filename string) (count int64) {

	// open audit record file
	r, err := Open(filename)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	var (
		header = r.ReadHeader()
		rec    = InitRecord(header.Type)
	)
	for {
		// read next record
		err := r.Next(rec)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}
		count++
	}
	return
}
