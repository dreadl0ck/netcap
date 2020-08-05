package transform

import (
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToFileTypesForIP() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {
			if file.Context.SrcIP == ipaddr || file.Context.DstIP == ipaddr {

				typ := file.ContentTypeDetected
				parts := strings.Split(file.ContentTypeDetected, ";")
				if len(parts) > 1 {
					typ = parts[0]
				}

				ent := trx.AddEntity("netcap.ContentType", typ)
				ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
				ent.AddProperty("path", "Path", "strict", profilesFile)
			}
		},
	)
}
