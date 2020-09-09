package transform

import (
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toFileTypesForIP() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, path string, ipaddr string) {
			if file.SrcIP == ipaddr || file.DstIP == ipaddr {
				typ := file.ContentTypeDetected
				parts := strings.Split(file.ContentTypeDetected, ";")
				if len(parts) > 1 {
					typ = parts[0]
				}

				ent := trx.AddEntityWithPath("netcap.ContentType", typ, path)
				ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)

			}
		},
	)
}
