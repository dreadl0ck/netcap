package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toJA3Hashes() {
	maltego.TLSClientHelloTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, hello *types.TLSClientHello, min, max uint64, path string, ipaddr string) {
			ent := trx.AddEntityWithPath("netcap.TLSClientHello", hello.Ja3, path)
			ent.AddProperty("ip", "IP", maltego.Strict, hello.SrcIP)
			ent.AddProperty("port", "Port", maltego.Strict, strconv.Itoa(int(hello.SrcPort)))
			ent.AddDisplayInformation(utils.CreateFlowIdent(hello.SrcIP, strconv.Itoa(int(hello.SrcPort)), hello.DstIP, strconv.Itoa(int(hello.DstPort)))+"<br>", "Flows")
		},
	)
}
