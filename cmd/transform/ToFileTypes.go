package transform

import (
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toFileTypes() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, path string, ipaddr string) {
			typ := file.ContentTypeDetected
			parts := strings.Split(file.ContentTypeDetected, ";")
			if len(parts) > 1 {
				typ = parts[0]
			}

			ent := trx.AddEntityWithPath("netcap.ContentType", typ, path)

			//// di := "<h3>File</h3><p>Timestamp: " + file.Timestamp + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.Context.SrcIP + "</p><p>DstIP: " + file.Context.DstIP + "</p><p>SrcPort: " + file.Context.SrcPort + "</p><p>DstPort: " + file.Context.DstPort + "</p><p>Location: " + file.Location + "</p>"
			//// ent.AddDisplayInformation(di, "Netcap Info")

			ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)

		},
	)
}
