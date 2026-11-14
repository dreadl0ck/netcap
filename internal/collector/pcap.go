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

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/pkg/errors"

	"github.com/dreadl0ck/netcap/internal/decoder/packet"
)

const errReadingPacketData = "error reading packet data"

// dltDescriptions maps PCAP Data Link Type (DLT) values to their standard protocol names
// Reference: https://www.tcpdump.org/linktypes.html (generated from the registry; labels by LINKTYPE value)
var dltDescriptions = map[int]string{
	0:   "DLT_NULL - BSD loopback encapsulation",
	1:   "DLT_EN10MB - IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical",
	2:   "DLT_EN3MB - Experimental Ethernet (3Mb)",
	3:   "DLT_AX25 - AX.25 layer 2 packets",
	4:   "DLT_PRONET - Reserved for Proteon ProNET Token Ring",
	5:   "DLT_CHAOS - Reserved for MIT Chaosnet",
	6:   "DLT_IEEE802 - IEEE 802.5 Token Ring; the IEEE802, without _5, in the DLT_ name is historical",
	7:   "DLT_ARCNET - Reserved for ARCNET Data Packets with BSD encapsulation",
	8:   "DLT_SLIP - SLIP, with a header giving packet direction",
	9:   "DLT_PPP - PPP",
	10:  "DLT_FDDI - FDDI, as specified by ANSI INCITS 239-1994",
	32:  "DLT_REDBACK_SMARTEDGE - Redback SmartEdge 400/800",
	50:  "DLT_PPP_SERIAL - PPP in HDLC-like framing",
	51:  "DLT_PPP_ETHER - PPPoE session packets",
	99:  "DLT_SYMANTEC_FIREWALL - Symantec Enterprise (ex-Axent Raptor) firewall",
	100: "DLT_ATM_RFC1483 - LLC/SNAP-encapsulated ATM",
	101: "DLT_RAW - IPv4 or IPv6 packets with no link-layer header",
	102: "DLT_SLIP_BSDOS - BSD/OS Serial Line IP",
	103: "DLT_PPP_BSDOS - BSD/OS Point-to-point Protocol",
	104: "DLT_C_HDLC - Cisco PPP with HDLC framing",
	105: "DLT_IEEE802_11 - IEEE 802.11 wireless LAN",
	106: "DLT_ATM_CLIP - Linux Classical IP over ATM",
	107: "DLT_FRELAY - Frame Relay LAPF",
	108: "DLT_LOOP - OpenBSD loopback encapsulation",
	109: "DLT_ENC - Encapsulated packets for IPsec",
	110: "LINKTYPE_LANE8023 - ATM LANE + IEEE 802.3",
	111: "DLT_HIPPI - NetBSD HIPPI",
	112: "DLT_HDLC - Cisco HDLC",
	113: "DLT_LINUX_SLL - Linux \"cooked\" capture encapsulation",
	114: "DLT_LTALK - Apple LocalTalk packets",
	115: "DLT_ECONET - Acorn Econet",
	116: "DLT_IPFILTER - OpenBSD ipfilter",
	117: "DLT_PFLOG - OpenBSD pflog; the link-layer header contains a struct pfloghdr structure, as defined...",
	118: "DLT_CISCO_IOS - Cisco internal use",
	119: "DLT_PRISM_HEADER - Prism monitor mode information, followed by an 802.11 frame",
	120: "DLT_AIRONET_HEADER - Reserved for Aironet 802.11 cards, with an Aironet link-layer header",
	122: "DLT_IP_OVER_FC - IP and ATM over Fibre Channel",
	123: "DLT_SUNATM - ATM traffic captured from a SunATM device",
	124: "DLT_RIO - RapidIO",
	125: "DLT_PCI_EXP - PCI Express",
	126: "DLT_AURORA - Xilinx Aurora",
	127: "DLT_IEEE802_11_RADIO - Radiotap link-layer information followed by an 802.11 header",
	128: "DLT_TZSP - Tazmen Sniffer Protocol (TZSP) is a generic encapsulation for any other link type,...",
	129: "DLT_ARCNET_LINUX - ARCnet Data Packets with Linux encapsulation",
	130: "DLT_JUNIPER_MLPPP - Juniper Networks private data link type",
	131: "DLT_JUNIPER_MLFR - Juniper Networks private data link type",
	132: "DLT_JUNIPER_ES - Juniper Networks private data link type",
	133: "DLT_JUNIPER_GGSN - Juniper Networks private data link type",
	134: "DLT_JUNIPER_MFR - Juniper Networks private data link type",
	135: "DLT_JUNIPER_ATM2 - Juniper Networks private data link type",
	136: "DLT_JUNIPER_SERVICES - Juniper Networks private data link type",
	137: "DLT_JUNIPER_ATM1 - Juniper Networks private data link type",
	138: "DLT_APPLE_IP_OVER_IEEE1394 - Apple IP-over-IEEE 1394 cooked header",
	139: "DLT_MTP2_WITH_PHDR - SS7 MTP2 packets, with a pseudo-header",
	140: "DLT_MTP2 - SS7 MTP2 packets",
	141: "DLT_MTP3 - SS7 MTP3 packets",
	142: "DLT_SCCP - SS7 SCCP packets",
	143: "DLT_DOCSIS - DOCSIS MAC frames, as described by the DOCSIS 4.0 MAC and Upper Layer Protocols...",
	144: "DLT_LINUX_IRDA - Linux-IrDA packets",
	145: "DLT_IBM_SP - IBM SP switch",
	146: "DLT_IBM_SN - IBM Next Federation switch",
	147: "DLT_USER0 - Reserved for private use",
	148: "DLT_USER1 - Reserved for private use",
	149: "DLT_USER2 - Reserved for private use",
	150: "DLT_USER3 - Reserved for private use",
	151: "DLT_USER4 - Reserved for private use",
	152: "DLT_USER5 - Reserved for private use",
	153: "DLT_USER6 - Reserved for private use",
	154: "DLT_USER7 - Reserved for private use",
	155: "DLT_USER8 - Reserved for private use",
	156: "DLT_USER9 - Reserved for private use",
	157: "DLT_USER10 - Reserved for private use",
	158: "DLT_USER11 - Reserved for private use",
	159: "DLT_USER12 - Reserved for private use",
	160: "DLT_USER13 - Reserved for private use",
	161: "DLT_USER14 - Reserved for private use",
	162: "DLT_USER15 - Reserved for private use",
	163: "DLT_IEEE802_11_RADIO_AVS - AVS monitor mode information followed by an 802.11 header",
	164: "DLT_JUNIPER_MONITOR - Juniper Networks private data link type",
	165: "DLT_BACNET_MS_TP - BACnet MS/TP frames",
	166: "DLT_PPP_PPPD - PPP preceded by a direction octet and an HDLC-like control field",
	167: "DLT_JUNIPER_PPPOE - Juniper Networks private data link type",
	168: "DLT_JUNIPER_PPPOE_ATM - Juniper Networks private data link type",
	169: "DLT_GPRS_LLC - General Packet Radio Service Logical Link Control, as defined by 3GPP TS 04.64",
	170: "DLT_GPF_T - Transparent-mapped generic framing procedure, as specified by ITU-T Recommendation...",
	171: "DLT_GPF_F - Frame-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303",
	172: "DLT_GCOM_T1E1 - Gcom's T1/E1 line monitoring equipment",
	173: "DLT_GCOM_SERIAL - Gcom's T1/E1 line monitoring equipment",
	174: "DLT_JUNIPER_PIC_PEER - Juniper Networks private data link type",
	175: "DLT_ERF_ETH - Endace ERF records of type TYPE_ETH",
	176: "DLT_ERF_POS - Endace ERF records of type TYPE_POS_HDLC",
	177: "DLT_LINUX_LAPD - Linux vISDN LAPD frames",
	178: "DLT_JUNIPER_ETHER - Juniper Networks private data link type",
	179: "DLT_JUNIPER_PPP - Juniper Networks private data link type",
	180: "DLT_JUNIPER_FRELAY - Juniper Networks private data link type",
	181: "DLT_JUNIPER_CHDLC - Juniper Networks private data link type",
	182: "DLT_MFR - FRF.16.1 Multi-Link Frame Relay frames",
	183: "DLT_JUNIPER_VP - Juniper Networks private data link type",
	184: "DLT_A429 - ARINC 429 frames",
	185: "DLT_A653_ICM - ARINC 653 interpartition communication messages",
	186: "DLT_USB_FREEBSD - USB with FreeBSD header",
	187: "DLT_BLUETOOTH_HCI_H4 - Bluetooth HCI UART Transport Layer packets",
	188: "DLT_IEEE802_16_MAC_CPS - IEEE 802.16 MAC Common Part Sublayer",
	189: "DLT_USB_LINUX - USB packets, beginning with a Linux USB header",
	190: "DLT_CAN20B - Controller Area Network (CAN) v",
	191: "DLT_IEEE802_15_4_LINUX - IEEE 802.15.4, with address fields padded, as is done by Linux drivers",
	192: "DLT_PPI - Per-Packet Information header preceding packet data",
	193: "DLT_IEEE802_16_MAC_CPS_RADIO - IEEE 802.16 MAC Common Part Sublayer plus radiotap header",
	194: "DLT_JUNIPER_ISM - Juniper Networks private data link type",
	195: "DLT_IEEE802_15_4_WITHFCS - IEEE 802.15.4 packets with FCS",
	196: "DLT_SITA - Various link-layer types, with a pseudo-header, for SITA",
	197: "DLT_ERF - Endace ERF records",
	198: "DLT_RAIF1 - Special header prepended to Ethernet packets when capturing from a u10 Networks board",
	199: "DLT_IPMB_KONTRON - IPMB packet for IPMI, beginning with a 2-byte header, followed by the I2C slave...",
	200: "DLT_JUNIPER_ST - Juniper Networks private data link type",
	201: "DLT_BLUETOOTH_HCI_H4_WITH_PHDR - Bluetooth HCI UART Transport Layer packets with a direction pseudo-header",
	202: "DLT_AX25_KISS - KISS frames between a host and an AX.25 TNC",
	203: "DLT_LAPD - Q.921 LAPD frames",
	204: "DLT_PPP_WITH_DIR - PPP, with a direction header",
	205: "DLT_C_HDLC_WITH_DIR - Cisco PPP with HDLC framing, with a direction header",
	206: "DLT_FRELAY_WITH_DIR - Frame Relay LAPF, with a direction header",
	207: "DLT_LAPB_WITH_DIR - X.25 LAPB, with a direction header",
	209: "DLT_I2C_LINUX - Linux I2C packets",
	210: "DLT_FLEXRAY - FlexRay automotive bus frames or symbols, preceded by a pseudo-header",
	211: "DLT_MOST - Media Oriented Systems Transport (MOST) bus for multimedia transport",
	212: "DLT_LIN - Local Interconnect Network (LIN) automotive bus, with a metadata header",
	213: "DLT_X2E_SERIAL - X2E-private data link type used for serial line capture",
	214: "DLT_X2E_XORAYA - X2E-private data link type used for the Xoraya data logger family",
	215: "DLT_IEEE802_15_4_NONASK_PHY - IEEE 802.15.4 packets with PHY header",
	216: "DLT_LINUX_EVDEV - Linux evdev events from /dev/input/eventN devices",
	217: "DLT_GSMTAP_UM - GSM Um interface, preceded by a \"gsmtap\" header",
	218: "DLT_GSMTAP_ABIS - GSM Abis interface, preceded by a \"gsmtap\" header",
	219: "DLT_MPLS - MPLS, with an MPLS label as the link-layer header",
	220: "DLT_USB_LINUX_MMAPPED - USB packets, beginning with an extended Linux USB header",
	221: "DLT_DECT - DECT packets, with a pseudo-header",
	222: "DLT_AOS - AOS Space Data Link Protocol",
	223: "DLT_WIHART - WirelessHART (Highway Addressable Remote Transducer) from the HART Communication...",
	224: "DLT_FC_2 - Fibre Channel FC-2 frames",
	225: "DLT_FC_2_WITH_FRAME_DELIMS - Fibre Channel FC-2 frames with SOF and EOF",
	226: "DLT_IPNET - Solaris ipnet",
	227: "DLT_CAN_SOCKETCAN - Controller Area Network (CAN) frames, with a metadata header",
	228: "DLT_IPV4 - IPv4 packets with no link-layer header",
	229: "DLT_IPV6 - IPv6 packets with no link-layer header",
	230: "DLT_IEEE802_15_4_NOFCS - IEEE 802.15.4 packets without FCS",
	231: "DLT_DBUS - Raw D-Bus messages",
	232: "DLT_JUNIPER_VS - Juniper Networks private data link type",
	233: "DLT_JUNIPER_SRX_E2E - Juniper Networks private data link type",
	234: "DLT_JUNIPER_FIBRECHANNEL - Juniper Networks private data link type",
	235: "DLT_DVB_CI - DVB-CI messages, with a pseudo-header",
	236: "DLT_MUX27010 - Variant of 3GPP TS 27.010 multiplexing protocol",
	237: "DLT_STANAG_5066_D_PDU - STANAG 5066 D_PDUs",
	238: "DLT_JUNIPER_ATM_CEMIC - Juniper Networks private data link type",
	239: "DLT_NFLOG - Linux netlink NETLINK NFLOG socket log messages",
	240: "DLT_NETANALYZER - Ethernet frames with Hilscher netANALYZER pseudo-header",
	241: "DLT_NETANALYZER_TRANSPARENT - Ethernet frames with netANALYZER pseudo-header, preamble and SFD, preceded by a Hilscher",
	242: "DLT_IPOIB - IP-over-InfiniBand",
	243: "DLT_MPEG_2_TS - MPEG-2 Transport Stream transport packets",
	244: "DLT_NG40 - Frames from ng4T GmbH's ng40 protocol tester",
	245: "DLT_NFC_LLCP - NFC Logical Link Control Protocol frames, with a pseudo-header",
	246: "LINKTYPE_PFSYNC - Packet filter state syncing",
	247: "DLT_INFINIBAND - InfiniBand data packets",
	248: "DLT_SCTP - SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6",
	249: "DLT_USBPCAP - USB packets, beginning with a USBPcap header",
	250: "DLT_RTAC_SERIAL - Serial-line packets from the Schweitzer Engineering Laboratories \"RTAC\" product",
	251: "DLT_BLUETOOTH_LE_LL - Bluetooth Low Energy link-layer packets",
	252: "DLT_WIRESHARK_UPPER_PDU - Upper-protocol layer PDU saves from Wireshark; the actual contents are determined by...",
	253: "DLT_NETLINK - Linux Netlink capture encapsulation",
	254: "DLT_BLUETOOTH_LINUX_MONITOR - Bluetooth Linux Monitor",
	255: "DLT_BLUETOOTH_BREDR_BB - Bluetooth Basic Rate and Enhanced Data Rate baseband packets",
	256: "DLT_BLUETOOTH_LE_LL_WITH_PHDR - Bluetooth Low Energy link-layer packets, with a pseudo-header",
	257: "DLT_PROFIBUS_DL - PROFIBUS data link layer packets",
	258: "DLT_PKTAP - Apple PKTAP capture encapsulation",
	259: "DLT_EPON - Ethernet-over-passive-optical-network packets, including preamble octets",
	260: "DLT_IPMI_HPM_2 - IPMI HPM.2 trace packets",
	261: "DLT_ZWAVE_R1_R2 - Z-Wave RF profile R1 and R2 packets",
	262: "DLT_ZWAVE_R3 - Z-Wave RF profile R3 packets",
	263: "DLT_WATTSTOPPER_DLM - WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol packets",
	264: "DLT_ISO_14443 - Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card,...",
	265: "DLT_RDS - IEC 62106 Radio data system (RDS) groups",
	266: "DLT_USB_DARWIN - USB packets captured on a Darwin-based operating system (macOS, etc.)",
	267: "DLT_OPENFLOW - OpenFlow messages with an additional 12-octet header, as used in OpenBSD switch...",
	268: "DLT_SDLC - SNA SDLC packets",
	269: "DLT_TI_LLN_SNIFFER - TI LLN sniffer frames",
	270: "DLT_LORATAP - LoRaWan packets with a LoRaTap pseudo-header",
	271: "DLT_VSOCK - Protocol for communication between host and guest machines in VMware and KVM hypervisors",
	272: "DLT_NORDIC_BLE - Messages to and from a Nordic Semiconductor nRF Sniffer for Bluetooth LE packets",
	273: "DLT_DOCSIS31_XRA31 - DOCSIS packets and bursts, preceded by a pseudo-header giving metadata about the packet",
	274: "DLT_ETHERNET_MPACKET - IEEE 802.3 mPackets",
	275: "DLT_DISPLAYPORT_AUX - DisplayPort AUX channel monitoring messages",
	276: "DLT_LINUX_SLL2 - Linux \"cooked\" capture encapsulation v2",
	277: "DLT_SERCOS_MONITOR - Sercos Monitor",
	278: "DLT_OPENVIZSLA - OpenVizsla FPGA-based USB sniffer frames",
	279: "DLT_EBHSCR - Elektrobit High Speed Capture and Replay (EBHSCR) format",
	280: "DLT_VPP_DISPATCH - Records in traces from the http://fd.io VPP graph dispatch tracer, in the the graph...",
	281: "DLT_DSA_TAG_BRCM - Ethernet frames, with a Broadcom switch tag inserted",
	282: "DLT_DSA_TAG_BRCM_PREPEND - Ethernet frames, with a Broadcom switch tag prepended",
	283: "DLT_IEEE802_15_4_TAP - IEEE 802.15.4 packets, with a pseudo-header containing TLVs with metadata preceding...",
	284: "DLT_DSA_TAG_DSA - Ethernet frames, with a Marvell DSA switch tag inserted",
	285: "DLT_DSA_TAG_EDSA - Ethernet frames, with a Marvell EDSA switch tag inserted",
	286: "DLT_ELEE - Reserved for ELEE lawful intercept protocol",
	287: "DLT_Z_WAVE_SERIAL - Serial frames transmitted between a host and a Z-Wave chip over an RS-232 or USB...",
	288: "DLT_USB_2_0 - USB 2.0, 1.1, or 1.0 packets",
	289: "DLT_ATSC_ALP - ATSC Link-Layer Protocol frames",
	290: "DLT_ETW - Event Tracing for Windows messages v1",
	291: "DLT_NETANALYZER_NG - Reserved for Hilscher Gesellschaft fuer Systemautomation mbH netANALYZER NG hardware...",
	292: "DLT_ZBOSS_NCP - ZBOSS NCP Serial Protocol, with a pseudo-header",
	293: "DLT_USB_2_0_LOW_SPEED - Low-Speed USB 2.0, 1.1, or 1.0 packets",
	294: "DLT_USB_2_0_FULL_SPEED - Full-Speed USB 2.0, 1.1, or 1.0 packets",
	295: "DLT_USB_2_0_HIGH_SPEED - High-Speed USB 2.0 packets",
	296: "DLT_AUERSWALD_LOG - Auerswald Logger Protocol packets",
	297: "DLT_ZWAVE_TAP - Z-Wave packets, with a metadata header",
	298: "DLT_SILABS_DEBUG_CHANNEL - Silicon Labs debug channel protocol, as described in the specification",
	299: "DLT_FIRA_UCI - Ultra-wideband (UWB) controller interface protocol (UCI)",
	300: "DLT_MDB - MDB (Multi-Drop Bus) messages, with a pseudo-header",
	301: "DLT_DECT_NR - DECT-2020 New Radio (NR) MAC layer",
	302: "DLT_EDK2_MM - edk2 mm request serialization protocol",
	303: "DLT_DEBUG_ONLY - Unstructured data for manual debugging only",
	304: "DLT_DECT_NR_TAP - DECT-2020 New Radio (NR) TAP with a custom metadata header prepended to a standard...",
	305: "DLT_ETW2 - Event Tracing for Windows messages v2",
}

// OpenPCAP opens a Packet Capture file.
func OpenPCAP(file string) (*pcapgo.Reader, *os.File, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}

	// try to create pcap reader
	r, err := pcapgo.NewReader(f)
	if err != nil {
		// Close the file before returning error
		f.Close()
		// Enhance the error with file type detection
		return nil, nil, enhancePcapError(file, err)
	}

	// Snaplen is advisory; retain an allocation ceiling for direct API callers.
	// Count/collect use the bounded reader, which also consumes recoverable bad records.
	r.SetSnaplen(maxInputPacket)
	return r, f, nil
}

// IsPcap classifies classic PCAP by magic, including gzip streams. It does not
// validate headers: unsupported or damaged PCAP stays on the PCAP error path.
func IsPcap(file string) (bool, error) {
	// get file handle
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	s, err := newCaptureStream(f)
	if err != nil {
		return false, err
	}
	var magic [4]byte
	if _, err := io.ReadFull(s.r, magic[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	switch binary.BigEndian.Uint32(magic[:]) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		return true, nil
	default:
		return false, nil
	}
}

// IsCapture recognizes supported capture containers independently of filenames.
func IsCapture(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	s, err := newCaptureStream(f)
	if err != nil {
		return false
	}
	var magic [4]byte
	if _, err := io.ReadFull(s.r, magic[:]); err != nil {
		return false
	}
	switch binary.BigEndian.Uint32(magic[:]) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a:
		return true
	}
	return false
}

// countPackets returns the number of packets in a PCAP file.
func countPackets(path string) (count int64, err error) {
	return countCaptureInput(context.Background(), path, false)
}

// CollectPcap implements parallel decoding of incoming packets.
func (c *Collector) CollectPcap(path string) (resultErr error) {
	return c.collectCaptureInput(path, false)
}

func (c *Collector) handleLinkType(lt layers.LinkType) error {
	c.captureLinkType = lt
	c.printlnStdOut("detected link type:", lt)

	layerType := linkTypeToLayerType(lt)
	if layerType == 0 || (lt == 149 && layerType != layers.LayerTypePktap) {
		linkTypeValue := int(lt)
		errMsg := fmt.Sprintf("unhandled link type: %s (raw value: %d, hex: 0x%02X)", lt, linkTypeValue, linkTypeValue)

		// Look up the standard DLT description if available
		if dltDesc, found := dltDescriptions[linkTypeValue]; found {
			errMsg += fmt.Sprintf("\n   Standard protocol: %s", dltDesc)
		}

		errMsg += "\n   For more information, see: https://www.tcpdump.org/linktypes.html"
		return errors.New(errMsg)
	}
	c.config.BaseLayer = layerType

	// Set the base layer type for the decoder package
	// This is used when decoding buffered packets during the flush phase
	packet.SetBaseLayerType(c.config.BaseLayer)

	return nil
}
