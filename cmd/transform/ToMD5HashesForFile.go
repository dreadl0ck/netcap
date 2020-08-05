package transform

import (
	"log"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func ToMD5HashesForFile() {

	var (
		name   string
		length int64
	)

	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {

			if len(name) == 0 {
				name = lt.Values["name"]
				var errLength error
				length, errLength = strconv.ParseInt(lt.Values["length"], 10, 64)
				if errLength != nil {
					log.Fatal("invalid length value: ", lt.Values["length"])
				}
				log.Println(lt.Values)
			}

			if file.Name == name && file.Length == length {

				var (
					ent = trx.AddEntity("netcap.MD5Hash", file.Hash)
					di  = "<h3>File</h3><p>Timestamp: " + file.Timestamp + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.Context.SrcIP + "</p><p>DstIP: " + file.Context.DstIP + "</p><p>SrcPort: " + file.Context.SrcPort + "</p><p>DstPort: " + file.Context.DstPort + "</p><p>Location: " + file.Location + "</p>"
				)
				ent.AddDisplayInformation(di, "Netcap Info")
				ent.AddProperty("path", "Path", "strict", file.Location)
			}
		},
	)
}
