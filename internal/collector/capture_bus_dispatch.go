package collector

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func captureBusDecoder(link layers.LinkType) gopacket.Decoder {
	switch link {
	case 3:
		return gopacket.DecodeFunc(decodeAX25)
	case 165:
		return gopacket.DecodeFunc(decodeBACnetMSTP)
	case 187:
		return gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return decodeBluetoothH4(data, p, false) })
	case 201:
		return gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error { return decodeBluetoothH4(data, p, true) })
	case 209:
		return gopacket.DecodeFunc(decodeI2CLinux)
	case 243:
		return gopacket.DecodeFunc(decodeMPEGTS)
	case 252:
		return gopacket.DecodeFunc(decodeUpperPDU)
	case 289:
		return gopacket.DecodeFunc(decodeALP)
	case 300:
		return gopacket.DecodeFunc(decodeMDB)
	}
	return nil
}
