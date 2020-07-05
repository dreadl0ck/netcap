package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"log"
	"strconv"
)

func ToMD5HashesForFile() {

	var ident string

	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {

			if len(ident) == 0 {
				ident = lt.Values["name"]
				log.Println(lt.Values)
			}

			if file.Name == ident {

				var (
					ent = trx.AddEntity("netcap.MD5Hash", file.Hash)
					di = "<h3>File</h3><p>Timestamp: " + file.Timestamp + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.Context.SrcIP + "</p><p>DstIP: " + file.Context.DstIP + "</p><p>SrcPort: " + file.Context.SrcPort + "</p><p>DstPort: " + file.Context.DstPort + "</p><p>Location: " + file.Location + "</p>"
				)
				ent.AddDisplayInformation(di, "Netcap Info")
				ent.AddProperty("path", "Path", "strict", file.Location)
			}
		},
	)
}
