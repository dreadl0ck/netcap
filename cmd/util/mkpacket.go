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

package util

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/gopacket/pcapgo"
)

func makePacket() {
	// read hex data from stdin
	d, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	// clean hex string
	final := strings.TrimSpace(
		strings.ReplaceAll(
			strings.ReplaceAll(string(d), " ", ""),
			"\n",
			"",
		),
	)

	// decode hex data
	data, err := hex.DecodeString(final)
	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(final, len(final), len(data))

	var (
		buf          = gopacket.NewSerializeBuffer()
		opts         = gopacket.SerializeOptions{}
		mac, _       = net.ParseMAC("00:00:5e:00:53:01")
		packetLayers = []gopacket.SerializableLayer{
			&layers.Ethernet{
				BaseLayer:    layers.BaseLayer{},
				SrcMAC:       mac,
				DstMAC:       mac,
				EthernetType: layers.EthernetTypeIPv4,
				//Length:       uint16(len(final)),
			},
			&layers.IPv4{
				BaseLayer:  layers.BaseLayer{},
				Version:    4,
				IHL:        5,
				TOS:        0,
				Length:     20 + uint16(len(data)),
				Id:         500,
				Flags:      2,
				FragOffset: 0,
				TTL:        128,
				Protocol:   layers.IPProtocolUDP,
				Checksum:   0,
				SrcIP:      net.IP{127, 0, 0, 1},
				DstIP:      net.IP{127, 0, 0, 1},
				Options:    nil,
				Padding:    nil,
			},
		}
	)

	if *flagMkPacket == "udp" {
		packetLayers = append(packetLayers, &layers.UDP{
			BaseLayer: layers.BaseLayer{},
			SrcPort:   52,
			DstPort:   53,
			Length:    uint16(len(data)),
			Checksum:  0,
		},
			gopacket.Payload(data),
		)
	}

	if *flagMkPacket == "tcp" {
		packetLayers = append(packetLayers, &layers.TCP{
			BaseLayer:  layers.BaseLayer{},
			SrcPort:    8000,
			DstPort:    8001,
			Seq:        0,
			Ack:        0,
			DataOffset: 0,
			FIN:        false,
			SYN:        false,
			RST:        false,
			PSH:        false,
			ACK:        false,
			URG:        false,
			ECE:        false,
			CWR:        false,
			NS:         false,
			Window:     0,
			Checksum:   0,
			Urgent:     0,
			Options:    nil,
			Padding:    nil,
		},
			gopacket.Payload(data),
		)
	}

	// construct packet
	err = gopacket.SerializeLayers(buf, opts, packetLayers...)
	packetData := buf.Bytes()

	// create pcapng file
	file := "packet.pcapng"
	f, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		errDefer := f.Close()
		if errDefer != nil {
			log.Fatal(errDefer)
		}
	}()

	// create pcapng writer
	r, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		errDefer := r.Flush()
		if errDefer != nil {
			log.Fatal(errDefer)
		}
	}()

	// write packet to disk
	err = r.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(packetData),
		Length:         len(packetData),
		InterfaceIndex: 0,
		AncillaryData:  nil,
	}, packetData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("done! created", file)
	return
}
