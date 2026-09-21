//go:build ja4plus

package packet

import (
	"github.com/dreadl0ck/tlsx"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/dreadl0ck/netcap/internal/ja4plusadapter"
)

func trackJA4LTiming(conn *connection, packet gopacket.Packet) {
	timestamp := packet.Metadata().Timestamp.UnixNano()
	if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
		if tcp.SYN && !tcp.ACK && conn.synTimestamp == 0 {
			conn.synTimestamp = timestamp
			if ipv4, ok := packet.NetworkLayer().(*layers.IPv4); ok {
				conn.synTTL = ipv4.TTL
			} else if ipv6, ok := packet.NetworkLayer().(*layers.IPv6); ok {
				conn.synTTL = ipv6.HopLimit
			}
		}
		if tcp.SYN && tcp.ACK && conn.synAckTimestamp == 0 {
			conn.synAckTimestamp = timestamp
		}
	}

	if conn.clientHelloTimestamp == 0 {
		if hello := tlsx.GetClientHello(packet); hello != nil {
			conn.clientHelloTimestamp = timestamp
			if hello.SNI != "" && conn.sni == "" {
				conn.sni = hello.SNI
			}
		}
	}
	if conn.serverHelloTimestamp == 0 {
		if tlsx.GetServerHello(packet) != nil {
			conn.serverHelloTimestamp = timestamp
		}
	}
}

func calculateJA4L(conn *connection) {
	conn.Connection.SynTimestamp = conn.synTimestamp
	conn.Connection.SynAckTimestamp = conn.synAckTimestamp
	conn.Connection.ClientHelloTimestamp = conn.clientHelloTimestamp
	conn.Connection.ServerHelloTimestamp = conn.serverHelloTimestamp
	conn.Connection.SynTtl = int32(conn.synTTL)

	if conn.synTimestamp > 0 && conn.synAckTimestamp > 0 {
		conn.Connection.TcpRttNanos = conn.synAckTimestamp - conn.synTimestamp
		conn.Connection.Ja4LClient = ja4plusadapter.ComputeJA4L(conn.Connection.TcpRttNanos, conn.synTTL)
	}
	if conn.clientHelloTimestamp > 0 && conn.serverHelloTimestamp > 0 {
		conn.Connection.TlsHandshakeNanos = conn.serverHelloTimestamp - conn.clientHelloTimestamp
		conn.Connection.Ja4LServer = ja4plusadapter.ComputeJA4L(conn.Connection.TlsHandshakeNanos, conn.synTTL)
	}
}
