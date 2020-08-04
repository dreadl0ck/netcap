package transform

import (
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"net"
	"strconv"

	//"strconv"
	"strings"
)

func ToDestinationIPs() {
	maltego.DeviceProfileTransform(
		maltego.CountPacketsContactIPs,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, profilesFile string, mac string) {
			if profile.MacAddr == mac {

				for _, ip := range profile.Contacts {

					var (
						ent      *maltego.EntityObj
						dnsNames = strings.Join(ip.DNSNames, "\n")
						val      = ip.Addr
					)
					if len(ip.Geolocation) > 0 {
						val += "\n" + ip.Geolocation
					}
					if len(dnsNames) > 0 {
						val += "\n" + dnsNames
					}

					if resolvers.IsPrivateIP(net.ParseIP(ip.Addr)) {
						ent = trx.AddEntity("netcap.InternalDestinationIP", val)
					} else {
						ent = trx.AddEntity("netcap.ExternalDestinationIP", val)
					}

					ent.AddProperty("geolocation", "Geolocation", "strict", ip.Geolocation)
					ent.AddProperty("dnsNames", "DNS Names", "strict", dnsNames)
					ent.AddProperty("timestamp", "Timestamp", "strict", profile.Timestamp)

					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ip.Addr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
					ent.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(profile.NumPackets, 10))

					ent.SetLinkLabel(strconv.FormatInt(ip.NumPackets, 10) + " pkts\n" + humanize.Bytes(ip.Bytes))
					ent.SetLinkThickness(maltego.GetThickness(uint64(ip.NumPackets), min, max))
				}
			}
		},
	)
}
