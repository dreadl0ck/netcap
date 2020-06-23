package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
)

func ToApplicationCategories() {
	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.MaltegoTransform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string, ipaddr string) {
			if profile.MacAddr == mac {

				for _, ip := range profile.Contacts {

					if ip.Addr == ipaddr {

						for _, proto := range ip.Protocols {
							if proto.Category != "" {
								ent := trx.AddEntity("maltego.Service", proto.Category)
								ent.SetType("maltego.Service")
								ent.SetValue(proto.Category)

								// di := "<h3>Traffic Category</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
								// ent.AddDisplayInformation(di, "Netcap Info")

								ent.AddProperty("mac", "MacAddress", "strict", mac)
								ent.AddProperty("ipaddr", "IPAddress", "strict", ip.Addr)
								ent.AddProperty("path", "Path", "strict", profilesFile)

								ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
								ent.SetLinkColor("#000000")
							}
						}

						break
					}
				}
				for _, ip := range profile.DeviceIPs {

					if ip.Addr == ipaddr {

						for _, proto := range ip.Protocols {
							if proto.Category != "" {
								ent := trx.AddEntity("maltego.Service", proto.Category)
								ent.SetType("maltego.Service")
								ent.SetValue(proto.Category)

								// di := "<h3>Traffic Category</h3><p>Timestamp first seen: " + ip.TimestampFirst + "</p>"
								// ent.AddDisplayInformation(di, "Netcap Info")

								ent.AddProperty("mac", "MacAddress", "strict", mac)
								ent.AddProperty("ipaddr", "IPAddress", "strict", ip.Addr)
								ent.AddProperty("path", "Path", "strict", profilesFile)

								ent.SetLinkLabel(strconv.FormatInt(int64(proto.Packets), 10) + " pkts")
								ent.SetLinkColor("#000000")
							}
						}

						break
					}
				}
			}
		},
	)
}
