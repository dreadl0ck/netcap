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
		func(lt maltego.LocalTransform, trx *maltego.Transform, file *types.File, min, max uint64, path string, ipaddr string) {
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
						ent = trx.AddEntityWithPath("maltego.Image", val, path)
					} else {
						ent = trx.AddEntityWithPath("netcap.File", val, path)
					}

					di := "<h3>File</h3><p>Timestamp: " + utils.UnixTimeToUTC(file.Timestamp) + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>ContentTypeDetected: " + file.ContentTypeDetected + "</p><p>Host: " + file.Host + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.SrcIP + "</p><p>DstIP: " + file.DstIP + "</p><p>SrcPort: " + strconv.FormatInt(int64(file.SrcPort), 10) + "</p><p>DstPort: " + strconv.FormatInt(int64(file.DstPort), 10) + "</p><p>Location: " + file.Location + "</p>"
					ent.AddDisplayInformation(di, "Netcap Info")

					if filepath.IsAbs(file.Location) {
						ent.SetIconURL("file://" + file.Location)
					} else {
						ent.SetIconURL("file://" + filepath.Join(filepath.Join(filepath.Dir(path), ".."), file.Location))
					}
					ent.AddProperty(maltego.PropertyIpAddr, maltego.PropertyIpAddrLabel, maltego.Strict, ipaddr)

					ent.AddProperty("location", "Location", maltego.Strict, file.Location)
					ent.AddProperty("name", "Name", maltego.Strict, file.Name)
					ent.AddProperty("length", "Length", maltego.Strict, strconv.FormatInt(file.Length, 10))
				}
			}
		},
	)
}
