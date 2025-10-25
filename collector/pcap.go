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

package collector

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/pkg/errors"
)

const errReadingPacketData = "error reading packet data"

// dltDescriptions maps PCAP Data Link Type (DLT) values to their standard protocol names
// Reference: https://www.tcpdump.org/linktypes.html
var dltDescriptions = map[int]string{
	0:   "DLT_NULL - BSD loopback encapsulation",
	1:   "DLT_EN10MB - IEEE 802.3 Ethernet",
	2:   "DLT_EN3MB - Experimental Ethernet (3Mb)",
	3:   "DLT_AX25 - Amateur Radio AX.25",
	4:   "DLT_PRONET - Proteon ProNET Token Ring",
	5:   "DLT_CHAOS - Chaos",
	6:   "DLT_IEEE802 - IEEE 802.5 Token Ring",
	7:   "DLT_ARCNET - ARCNET Data Packets",
	8:   "DLT_SLIP - Serial Line IP",
	9:   "DLT_PPP - Point-to-Point Protocol",
	10:  "DLT_FDDI - FDDI",
	50:  "DLT_PPP_SERIAL - PPP over serial with HDLC encapsulation",
	51:  "DLT_PPP_ETHER - PPPoE",
	100: "DLT_ATM_RFC1483 - LLC-encapsulated ATM",
	101: "DLT_RAW - Raw IP",
	104: "DLT_C_HDLC - Cisco HDLC",
	105: "DLT_IEEE802_11 - IEEE 802.11 wireless",
	107: "DLT_FRELAY - Frame Relay",
	108: "DLT_LOOP - OpenBSD loopback",
	113: "DLT_LINUX_SLL - Linux cooked sockets",
	114: "DLT_LTALK - Apple LocalTalk",
	117: "DLT_PFLOG - OpenBSD PF firewall logs",
	119: "DLT_IEEE802_11_PRISM - Prism monitor mode",
	122: "DLT_IP_OVER_FC - RFC 2625 IP-over-Fibre Channel",
	123: "DLT_SUNATM - Solaris+SunATM",
	127: "DLT_IEEE802_11_RADIO - 802.11 plus radiotap header",
	128: "DLT_ARCNET_LINUX - ARCNET Linux",
	129: "DLT_APPLE_IP_OVER_IEEE1394 - Apple IP-over-IEEE 1394",
	138: "DLT_MTP2_WITH_PHDR - SS7 MTP2 with pseudo-header",
	139: "DLT_MTP2 - SS7 MTP2",
	140: "DLT_MTP3 - SS7 MTP3",
	141: "DLT_SCCP - SS7 SCCP",
	142: "DLT_DOCSIS - DOCSIS MAC frames",
	143: "DLT_LINUX_IRDA - Linux IrDA",
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
	163: "DLT_IEEE802_11_RADIO_AVS - 802.11 plus AVS radio header",
	165: "DLT_BACNET_MS_TP - BACnet MS/TP",
	166: "DLT_PPP_PPPD - PPP in HDLC-like framing",
	169: "DLT_GPRS_LLC - General Packet Radio Service LLC",
	170: "DLT_GPF_T - GPF-T",
	171: "DLT_GPF_F - GPF-F",
	177: "DLT_LINUX_LAPD - Linux vISDN LAPD",
	187: "DLT_BLUETOOTH_HCI_H4 - Bluetooth HCI UART transport",
	189: "DLT_USB_LINUX - USB with Linux header",
	192: "DLT_PPI - Per-Packet Information",
	195: "DLT_IEEE802_15_4 - IEEE 802.15.4 wireless",
	196: "DLT_SITA - SITA",
	197: "DLT_ERF - Endace ERF records",
	201: "DLT_BLUETOOTH_HCI_H4_WITH_PHDR - Bluetooth HCI UART with pseudo-header",
	202: "DLT_AX25_KISS - AX.25 with KISS header",
	203: "DLT_LAPD - LAPD",
	204: "DLT_PPP_WITH_DIR - PPP with direction pseudo-header",
	205: "DLT_C_HDLC_WITH_DIR - Cisco HDLC with direction pseudo-header",
	206: "DLT_FRELAY_WITH_DIR - Frame Relay with direction pseudo-header",
	209: "DLT_IPMB_LINUX - IPMB on Linux",
	215: "DLT_IEEE802_15_4_NONASK_PHY - IEEE 802.15.4 with non-ASK PHY",
	220: "DLT_USB_LINUX_MMAPPED - USB with padded Linux header",
	224: "DLT_FC_2 - Fibre Channel FC-2",
	225: "DLT_FC_2_WITH_FRAME_DELIMS - Fibre Channel FC-2 with frame delimiters",
	226: "DLT_IPNET - Solaris ipnet",
	227: "DLT_CAN_SOCKETCAN - CAN-bus with SocketCAN headers",
	228: "DLT_IPV4 - Raw IPv4",
	229: "DLT_IPV6 - Raw IPv6",
	230: "DLT_IEEE802_15_4_NOFCS - IEEE 802.15.4 without FCS",
	231: "DLT_DBUS - D-Bus messages",
	235: "DLT_DVB_CI - DVB-CI",
	236: "DLT_MUX27010 - Variant of 3GPP TS 27.010",
	237: "DLT_STANAG_5066_D_PDU - STANAG 5066 D_PDUs",
	239: "DLT_NFLOG - Linux netfilter log messages",
	240: "DLT_NETANALYZER - Hilscher netANALYZER",
	241: "DLT_NETANALYZER_TRANSPARENT - Hilscher netANALYZER transparent",
	242: "DLT_IPOIB - IP-over-InfiniBand",
	243: "DLT_MPEG_2_TS - MPEG-2 Transport Stream",
	244: "DLT_NG40 - ng4T GmbH ng40",
	245: "DLT_NFC_LLCP - NFC LLCP",
	247: "DLT_INFINIBAND - InfiniBand",
	248: "DLT_SCTP - SCTP",
	249: "DLT_USBPCAP - USB with USBPcap header",
	250: "DLT_RTAC_SERIAL - Schweitzer Engineering Laboratories RTAC serial",
	251: "DLT_BLUETOOTH_LE_LL - Bluetooth Low Energy link layer",
	253: "DLT_NETLINK - Linux netlink",
	254: "DLT_BLUETOOTH_LINUX_MONITOR - Bluetooth Linux Monitor",
	255: "DLT_BLUETOOTH_BREDR_BB - Bluetooth BR/EDR Baseband",
	256: "DLT_BLUETOOTH_LE_LL_WITH_PHDR - Bluetooth Low Energy with pseudo-header",
	257: "DLT_PROFIBUS_DL - PROFIBUS data link layer",
	258: "DLT_PKTAP - Apple PKTAP",
	259: "DLT_EPON - Ethernet Passive Optical Network",
	260: "DLT_IPMI_HPM_2 - IPMI trace packets",
	261: "DLT_ZWAVE_R1_R2 - Z-Wave R1/R2",
	262: "DLT_ZWAVE_R3 - Z-Wave R3",
	263: "DLT_WATTSTOPPER_DLM - WattStopper Digital Lighting Management",
	264: "DLT_ISO_14443 - ISO 14443 contactless smartcard",
	265: "DLT_RDS - RadioData System",
	266: "DLT_USB_DARWIN - USB with Darwin header",
	268: "DLT_SDLC - IBM SDLC",
	269: "DLT_LORATAP - LoRaTap",
	270: "DLT_VSOCK - Linux vsock",
	271: "DLT_NORDIC_BLE - Nordic Semiconductor Bluetooth LE sniffer",
	272: "DLT_DOCSIS31_XRA31 - DOCSIS 3.1 Downstream RF Interface",
	273: "DLT_ETHERNET_MPACKET - mPackets",
	274: "DLT_DISPLAYPORT_AUX - DisplayPort AUX channel",
	275: "DLT_LINUX_SLL2 - Linux cooked sockets v2",
	276: "DLT_OPENVIZSLA - OpenVizsla",
	278: "DLT_EBHSCR - Elektrobit High Speed Capture and Replay",
	279: "DLT_VPP_DISPATCH - VPP graph dispatcher trace",
	280: "DLT_DSA_TAG_BRCM - Broadcom switch tag",
	281: "DLT_DSA_TAG_BRCM_PREPEND - Broadcom switch tag (prepended)",
	282: "DLT_IEEE802_15_4_TAP - IEEE 802.15.4 with TAP",
	283: "DLT_DSA_TAG_DSA - Marvell DSA",
	284: "DLT_DSA_TAG_EDSA - Marvell EDSA",
	285: "DLT_ELEE - ELEE lawful intercept",
	286: "DLT_Z_WAVE_SERIAL - Z-Wave serial",
	287: "DLT_USB_2_0 - USB 2.0/1.1/1.0",
	288: "DLT_ATSC_ALP - ATSC Link-Layer Protocol",
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
		return nil, nil, err
	}

	return r, f, nil
}

// IsPcap checks whether a file is a PCAP file.
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

	// try to create pcap reader
	_, err = pcapgo.NewReader(f)
	if err != nil {
		// file exists but is not a pcap
		// dont return error in this case
		return false, nil
	}

	return true, nil
}

// countPackets returns the number of packets in a PCAP file.
func countPackets(path string) (count int64, err error) {
	// get reader and file handle
	r, f, err := OpenPCAP(path)
	if err != nil {
		return
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	for {
		// loop over packets and discard all data
		_, _, err = r.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return count, errors.Wrap(err, errReadingPacketData)
		}

		// increment counter
		count++
	}

	return count, nil
}

// CollectPcap implements parallel decoding of incoming packets.
func (c *Collector) CollectPcap(path string) error {
	// Recover from any panics during processing
	defer c.recoverFromPanic()

	// stat input file
	stat, err := os.Stat(path)
	if err != nil {
		return errors.Wrap(err, "failed to open file")
	}

	// file exists.
	c.clearLine()
	c.printlnStdOut("opening", path+" | size:", humanize.Bytes(uint64(stat.Size())))

	// set input filesize on collector
	c.inputSize = stat.Size()

	// display total packet count
	start := time.Now()

	c.printStdOut("counting packets...")

	c.numPackets, err = countPackets(path)
	if err != nil && !(errors.Is(err, io.EOF)) {
		return err
	}

	c.clearLine()
	c.printlnStdOut("counting packets... done.", c.numPackets, "packets found in", time.Since(start))

	r, f, err := OpenPCAP(path)
	if err != nil {
		return err
	}

	defer func() {
		errClose := f.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println(errClose)
		}
	}()

	if err = c.handleLinkType(r.LinkType()); err != nil {
		return err
	}

	// initialize collector
	if err = c.Init(); err != nil {
		return err
	}

	var (
		data         []byte
		ci           gopacket.CaptureInfo
		stopProgress = c.printProgressInterval()
	)

	for { // fetch the next packet data and packet header
		data, ci, err = r.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return errors.Wrap(err, errReadingPacketData+" file: "+path)
		}

		// increment atomic packet counter
		atomic.AddInt64(&c.current, 1)

		// must be locked, otherwise a race occurs when sending a SIGINT
		//  and triggering wg.Wait() in another goroutine...
		c.statMutex.Lock()

		// increment wait group for packet processing
		c.wg.Add(1)

		c.statMutex.Unlock()

		c.handleRawPacketData(data, &ci)
	}

	// Stop progress reporting
	stopProgress <- struct{}{}

	// run cleanup on channel exit
	c.cleanup(false)

	return nil
}

func (c *Collector) handleLinkType(lt layers.LinkType) error {
	c.printlnStdOut("detected link type:", lt)

	// TODO: why does this not work?
	//c.config.BaseLayer = lt.LayerType()

	switch lt {
	case layers.LinkTypeEthernet:
		c.config.BaseLayer = layers.LayerTypeEthernet
	case layers.LinkTypeRaw:
		c.config.BaseLayer = layers.LayerTypeIPv4
	case layers.LinkTypeIPv4:
		c.config.BaseLayer = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		c.config.BaseLayer = layers.LayerTypeIPv6
	case layers.LinkTypeNull:
		c.config.BaseLayer = layers.LayerTypeLoopback
	case layers.LinkTypeFDDI:
		c.config.BaseLayer = layers.LayerTypeFDDI
	case layers.LinkTypeIEEE802_11:
		c.config.BaseLayer = layers.LayerTypeDot11
	case layers.LinkTypeIEEE80211Radio:
		c.config.BaseLayer = layers.LayerTypeRadioTap
	case layers.LinkTypePPP:
		c.config.BaseLayer = layers.LayerTypePPP
	case layers.LinkTypeLinuxSLL:
		c.config.BaseLayer = layers.LayerTypeLinuxSLL
	default:
		linkTypeValue := int(lt)
		errMsg := fmt.Sprintf("unhandled link type: %s (raw value: %d, hex: 0x%02X)", lt, linkTypeValue, linkTypeValue)

		// Look up the standard DLT description if available
		if dltDesc, found := dltDescriptions[linkTypeValue]; found {
			errMsg += fmt.Sprintf("\n   Standard protocol: %s", dltDesc)
		}

		errMsg += "\n   For more information, see: https://www.tcpdump.org/linktypes.html"
		return errors.New(errMsg)
	}

	return nil
}
