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
	case types.Type_NC_PKTAP:
		record = new(types.PKTAP)
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
	case types.Type_NC_TLSCertificate:
		record = new(types.TLSCertificate)
	case types.Type_NC_Software:
		record = new(types.Software)
	case types.Type_NC_Service:
		record = new(types.Service)
	case types.Type_NC_Secret:
		record = new(types.Secret)
	case types.Type_NC_SSH:
		record = new(types.SSH)
	case types.Type_NC_Vulnerability:
		record = new(types.Vulnerability)
	case types.Type_NC_Exploit:
		record = new(types.Exploit)
	case types.Type_NC_Host:
		record = new(types.Host)
	case types.Type_NC_Mail:
		record = new(types.Mail)
	case types.Type_NC_Alert:
		record = new(types.Alert)
	case types.Type_NC_FTP:
		record = new(types.FTP)
	case types.Type_NC_IRC:
		record = new(types.IRC)
	case types.Type_NC_SMB:
		record = new(types.SMB)
	case types.Type_NC_IMAP:
		record = new(types.IMAP)
	case types.Type_NC_BGP:
		record = new(types.BGP)
	case types.Type_NC_RADIUS:
		record = new(types.RADIUS)
	case types.Type_NC_Syslog:
		record = new(types.Syslog)
	case types.Type_NC_RDP:
		record = new(types.RDP)
	case types.Type_NC_DNP3:
		record = new(types.DNP3)
	case types.Type_NC_SOCKS:
		record = new(types.SOCKS)
	case types.Type_NC_GTP:
		record = new(types.GTP)
	case types.Type_NC_PPPoE:
		record = new(types.PPPoE)
	case types.Type_NC_PPP:
		record = new(types.PPP)
	case types.Type_NC_RMCP:
		record = new(types.RMCP)
	case types.Type_NC_STP:
		record = new(types.STP)
	case types.Type_NC_MLDv2MulticastListenerQuery:
		record = new(types.MLDv2MulticastListenerQuery)
	case types.Type_NC_MLDv2MulticastListenerReport:
		record = new(types.MLDv2MulticastListenerReport)
	case types.Type_NC_OPCUA:
		record = new(types.OPCUA)
	case types.Type_NC_S7Comm:
		record = new(types.S7Comm)
	case types.Type_NC_MQTTSN:
		record = new(types.MQTTSN)
	case types.Type_NC_BACnetIP:
		record = new(types.BACnetIP)
	case types.Type_NC_IEC62351:
		record = new(types.IEC62351)
	case types.Type_NC_PROFINET:
		record = new(types.PROFINET)
	case types.Type_NC_QUIC:
		record = new(types.QUIC)
	case types.Type_NC_QUICClientHello:
		record = new(types.QUICClientHello)
	case types.Type_NC_LLMNR:
		record = new(types.LLMNR)
	case types.Type_NC_STUN:
		record = new(types.STUN)
	case types.Type_NC_Kerberos:
		record = new(types.Kerberos)
	case types.Type_NC_TACACS:
		record = new(types.TACACS)
	case types.Type_NC_NetFlowV9:
		record = new(types.NetFlowV9)
	case types.Type_NC_DCERPC:
		record = new(types.DCERPC)
	case types.Type_NC_OCSP:
		record = new(types.OCSP)
	case types.Type_NC_IPP:
		record = new(types.IPP)
	case types.Type_NC_PIM:
		record = new(types.PIM)
	case types.Type_NC_Zabbix:
		record = new(types.Zabbix)
	case types.Type_NC_CLDAP:
		record = new(types.CLDAP)
	case types.Type_NC_ISIS:
		record = new(types.ISIS)
	case types.Type_NC_RARP:
		record = new(types.RARP)
	case types.Type_NC_Protobuf:
		record = new(types.Protobuf)
	case types.Type_NC_Header:
		// NC_Header is a file header type, not an audit record type
		// Return nil to indicate this type should not be initialized as a record
		return nil
	default:
		// Unknown type: return nil instead of panicking to prevent webui crashes
		// when reading audit files produced by a different netcap version.
		return nil
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
