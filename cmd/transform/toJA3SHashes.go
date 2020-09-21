package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"strconv"
)

func toJA3SHashes() {

	maltego.TLSServerHelloTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, hello *types.TLSServerHello, min, max uint64, path string, ipaddr string) {

			ent := trx.AddEntityWithPath("netcap.TLSServerHello", hello.Ja3S, path)
			ent.AddProperty("ip", "IP", maltego.Strict, hello.SrcIP)
			ent.AddProperty("port", "Port", maltego.Strict, strconv.Itoa(int(hello.SrcPort)))
			ent.AddDisplayInformation(utils.CreateFlowIdent(hello.SrcIP, strconv.Itoa(int(hello.SrcPort)), hello.DstIP, strconv.Itoa(int(hello.DstPort)))+"<br>", "Flows")
		},
	)
}
