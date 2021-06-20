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

package io

import (
	"errors"
	"io"

	"github.com/gogo/protobuf/proto"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// InitRecord initializes a new record of the given type
// that conforms to the proto.Message interface
// if netcap is extended with new audit records they need to be added here as well.
func InitRecord(typ types.Type) (record proto.Message) {
	switch typ {
	case types.Type_NC_Ethernet:
		record = new(types.Ethernet)
	case types.Type_NC_ARP:
		record = new(types.ARP)
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
	case types.Type_NC_USBRequestBlockSetup:
		record = new(types.USBRequestBlockSetup)
	case types.Type_NC_LCM:
		record = new(types.LCM)
	case types.Type_NC_MPLS:
		record = new(types.MPLS)
	case types.Type_NC_Modbus:
		record = new(types.Modbus)
	case types.Type_NC_OSPFv2:
		record = new(types.OSPFv2)
	case types.Type_NC_OSPFv3:
		record = new(types.OSPFv3)
	case types.Type_NC_BFD:
		record = new(types.BFD)
	case types.Type_NC_GRE:
		record = new(types.GRE)
	case types.Type_NC_FDDI:
		record = new(types.FDDI)
	case types.Type_NC_EAP:
		record = new(types.EAP)
	case types.Type_NC_VRRPv2:
		record = new(types.VRRPv2)
	case types.Type_NC_EAPOL:
		record = new(types.EAPOL)
	case types.Type_NC_EAPOLKey:
		record = new(types.EAPOLKey)
	case types.Type_NC_CiscoDiscovery:
		record = new(types.CiscoDiscovery)
	case types.Type_NC_CiscoDiscoveryInfo:
		record = new(types.CiscoDiscoveryInfo)
	case types.Type_NC_NortelDiscovery:
		record = new(types.NortelDiscovery)
	case types.Type_NC_CIP:
		record = new(types.CIP)
	case types.Type_NC_ENIP:
		record = new(types.ENIP)
	case types.Type_NC_DeviceProfile:
		record = new(types.DeviceProfile)
	case types.Type_NC_File:
		record = new(types.File)
	case types.Type_NC_SMTP:
		record = new(types.SMTP)
	case types.Type_NC_Diameter:
		record = new(types.Diameter)
	case types.Type_NC_POP3:
		record = new(types.POP3)
	case types.Type_NC_TLSServerHello:
		record = new(types.TLSServerHello)
	case types.Type_NC_Software:
		record = new(types.Software)
	case types.Type_NC_Service:
		record = new(types.Service)
	case types.Type_NC_Credentials:
		record = new(types.Credentials)
	case types.Type_NC_SSH:
		record = new(types.SSH)
	case types.Type_NC_Vulnerability:
		record = new(types.Vulnerability)
	case types.Type_NC_Exploit:
		record = new(types.Exploit)
	case types.Type_NC_IPProfile:
		record = new(types.IPProfile)
	case types.Type_NC_Mail:
		record = new(types.Mail)
	case types.Type_NC_Alert:
		record = new(types.Alert)
	default:
		panic("InitRecord: unknown type: " + typ.String())
	}

	return record
}

// Count returns the total number of records found in an audit record file
// it does not return an error in case of a regular EOF
// but will return an error in case of an unexpected EOF.
func Count(filename string) (count int64, err error) {
	// open audit record file
	r, err := Open(filename, defaults.BufferSize)
	if err != nil {
		return 0, err
	}

	defer func() {
		errClose := r.Close()
		if errClose != nil {
			ioLog.Info("failed to close file",
				zap.Error(errClose),
			)
		}
	}()

	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		return 0, errFileHeader
	}

	rec := InitRecord(header.Type)

	for {
		// read next record
		err = r.Next(rec)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}
