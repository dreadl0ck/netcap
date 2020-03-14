// +build windows
package dpi

import "github.com/dreadl0ck/gopacket"

func Init() {
}

func Destroy() {
}

func GetProtocols(packet gopacket.Packet) map[string]struct{} {
	var uniqueResults = make(map[string]struct{})
	return uniqueResults
}