package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func toJA3SHashes() {

	maltego.TLSServerHelloTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, hello *types.TLSServerHello, min, max uint64, path string, ipaddr string) {

			ent := trx.AddEntityWithPath("netcap.TLSServerHello", hello.Ja3S, path)
			//ent.SetLinkLabel(humanize.Bytes(uint64(hello.SNI)))
			//ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))

			ent.AddProperty("ip", "IP", "strict", hello.SrcIP)
			ent.AddProperty("port", "Port", "strict", strconv.Itoa(int(hello.SrcPort)))
		},
	)
}
