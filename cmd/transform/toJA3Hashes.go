package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toJA3Hashes() {

	maltego.TLSClientHelloTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, hello *types.TLSClientHello, min, max uint64, path string, ipaddr string) {

			ent := trx.AddEntityWithPath("netcap.TLSClientHello", hello.Ja3 + "\n" + hello.SrcIP + ":" + strconv.Itoa(int(hello.SrcPort)), path)
			ent.AddProperty("ip", "IP", "strict", hello.SrcIP)
			ent.AddProperty("port", "Port", "strict", strconv.Itoa(int(hello.SrcPort)))
		},
	)
}
