// +build windows
package dpi

// this file function stubs for windows that do nothing, but allow us to compile
// getting the C bindings to cross compile for windows is a pain
// so currently no DPI support for windows

import (
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
)

func Init() {}

func Destroy() {}

func GetProtocols(packet gopacket.Packet) map[string]struct{} {
	var uniqueResults = make(map[string]struct{})
	return uniqueResults
}

func NewProto(i *struct{}) *types.Protocol {
	return &types.Protocol{}
}
