package transform

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toFilesForContentType() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {
			if ipaddr == "" || file.SrcIP == ipaddr || file.DstIP == ipaddr {

				var (
					ct  = lt.Values["properties.contenttype"]
					typ = file.ContentTypeDetected
				)

				// ignore encoding value when matching
				parts := strings.Split(file.ContentTypeDetected, ";")
				if len(parts) > 1 {
					typ = parts[0]
				}

				if typ == ct { // TODO: make a single file constructor and reuse it in toFiles!
					var (
						ent *maltego.EntityObj
						val = file.Name + "\n" + strconv.FormatInt(file.Length, 10) + " bytes"
					)
					if strings.HasPrefix(ct, "image/") {
						ent = trx.AddEntity("maltego.Image", val)
					} else {
						ent = trx.AddEntity("netcap.File", val)
					}

					di := "<h3>File</h3><p>Timestamp: " + utils.UnixTimeToUTC(file.Timestamp) + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.SrcIP + "</p><p>DstIP: " + file.DstIP + "</p><p>SrcPort: " + strconv.FormatInt(int64(file.SrcPort), 10) + "</p><p>DstPort: " + strconv.FormatInt(int64(file.DstPort), 10) + "</p><p>Location: " + file.Location + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					if filepath.IsAbs(file.Location) {
						ent.SetIconURL("file://" + file.Location)
					} else {
						ent.SetIconURL("file://" + filepath.Join(filepath.Join(filepath.Dir(profilesFile), ".."), file.Location))
					}
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
