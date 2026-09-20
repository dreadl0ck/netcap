//go:build !ja4plus

package packet

import (
	"github.com/dreadl0ck/tlsx"
	"github.com/gopacket/gopacket"
)

func trackJA4LTiming(conn *connection, packet gopacket.Packet) {
	if conn.sni == "" {
		if hello := tlsx.GetClientHello(packet); hello != nil {
			conn.sni = hello.SNI
		}
	}
}

func calculateJA4L(*connection) {}
