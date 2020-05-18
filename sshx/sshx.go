// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshx

import (
	"encoding/hex"
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/gopacket/layers"
	"log"
)

func GetClientHello(p gopacket.Packet) *KexInitMsg {
	if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		// cast TCP layer
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			log.Println("Could not decode TCP layer")
			return nil
		}

		if tcp.SYN {
			// Connection setup
		} else if tcp.FIN {
			// Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			// Acknowledgement packet
		} else if tcp.RST {
			// Unexpected packet
		} else {
			// data packet

			fmt.Println(p)
			fmt.Println(hex.Dump(p.Data()))

			var acceptMsg ServiceAcceptMsg
			err := Unmarshal(p.Data(), &acceptMsg)
			if err == nil {
				fmt.Println("got acceptMsg:", acceptMsg)
				return nil
			}

			var initMsg KexInitMsg
			err = Unmarshal(p.Data(), &initMsg)
			if err == nil {
				fmt.Println("got initMsg:", acceptMsg)
				return &initMsg
			}

			//// process SSH client hello
			//clientHello := (p)
			//if clientHello != nil {
			//	destination := "[" + p.NetworkLayer().NetworkFlow().Dst().String() + ":" + p.TransportLayer().TransportFlow().Dst().String() + "]"
			//	log.Printf("%s Client hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			//}
			//
			//return clientHello
		}
	}

	return nil
}

func GetServerHello(p gopacket.Packet) {

}
