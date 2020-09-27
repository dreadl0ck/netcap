package transform

import (
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toICMPV6ControlMessages() {
	maltego.ICMPv6Transform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, icmp *types.ICMPv6, min, max uint64, path string, ipaddr string) {

			ent := trx.AddEntityWithPath("netcap.ICMPv6ControlMessageType", layers.ICMPv6TypeCode(icmp.TypeCode).String(), path)
			ent.AddProperty("code", "Code", maltego.Strict, strconv.Itoa(int(icmp.TypeCode)))
		},
	)
}
