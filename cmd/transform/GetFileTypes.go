package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strings"
)

func GetFileTypes() {
	maltego.FilesTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, file *types.File, min, max uint64, profilesFile string, ipaddr string) {
			if file.Context.SrcIP == ipaddr || file.Context.DstIP == ipaddr {

				typ := file.ContentTypeDetected
				parts := strings.Split(file.ContentTypeDetected, ";")
				if len(parts) > 1 {
					typ = parts[0]
				}
				ctype := maltego.EscapeText(typ)

				ent := trx.AddEntity("netcap.ContentType", ctype)
				ent.SetType("netcap.ContentType")

				ent.SetValue(ctype)

				//// di := "<h3>File</h3><p>Timestamp: " + file.Timestamp + "</p><p>Source: " + file.Source + "</p><p>MD5: " + file.Hash + "</p><p>ContentType: " + file.ContentType + "</p><p>Length: " + strconv.Itoa(int(file.Length)) + "</p><p>Ident: " + file.Ident + "</p><p>SrcIP: " + file.Context.SrcIP + "</p><p>DstIP: " + file.Context.DstIP + "</p><p>SrcPort: " + file.Context.SrcPort + "</p><p>DstPort: " + file.Context.DstPort + "</p><p>Location: " + file.Location + "</p>"
				//// ent.AddDisplayInformation(di, "Netcap Info")

				ent.AddProperty("ipaddr", "IPAddress", "strict", ipaddr)
				ent.AddProperty("path", "Path", "strict", profilesFile)

				//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
			}
		},
	)
}
