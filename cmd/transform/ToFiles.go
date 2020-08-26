package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toFiles() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {
			if file.SrcIP == ipaddr {
				if file.Name != "" {
					ent := trx.AddEntity("netcap.File", file.Name+"\n"+file.ContentType)

					di := "<h3>File</h3><p>Timestamp: " + utils.UnixTimeToUTC(file.Timestamp) + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.SrcIP + "</p><p>DstIP: " + file.DstIP + "</p><p>SrcPort: " + strconv.FormatInt(int64(file.SrcPort), 10) + "</p><p>DstPort: " + strconv.FormatInt(int64(file.DstPort), 10) + "</p><p>Location: " + file.Location + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
					ent.AddProperty("location", "Location", "strict", file.Location)
					ent.AddProperty("name", "Name", "strict", file.Name)
					ent.AddProperty("length", "Length", "strict", strconv.FormatInt(file.Length, 10))
				}
			}
		},
	)
}
