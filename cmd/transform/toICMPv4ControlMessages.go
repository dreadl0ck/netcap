package transform

import (
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toICMPV4ControlMessages() {
	maltego.ICMPv4Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, icmp *types.ICMPv4, min, max uint64, path string, ipaddr string) {

			ent := trx.AddEntityWithPath("netcap.ICMPv4ControlMessageType", layers.ICMPv4TypeCode(icmp.TypeCode).String(), path)
			ent.AddProperty("code", "Code", maltego.Strict, strconv.Itoa(int(icmp.TypeCode)))
		},
	)
}
