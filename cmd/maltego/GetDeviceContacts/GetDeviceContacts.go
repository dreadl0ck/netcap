package main

import (
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"net"
	"strconv"

	//"strconv"
	"strings"
)

func main() {
	maltego.DeviceProfileTransform(
		maltego.CountPacketsContactIPs,
		func(trx *maltego.MaltegoTransform, profile *types.DeviceProfile, minPackets, maxPackets uint64, profilesFile string, mac string) {
			if profile.MacAddr == mac {

				for _, ip := range profile.Contacts {

					var ent *maltego.MaltegoEntityObj
					var contactType string
					if resolvers.IsPrivateIP(net.ParseIP(ip.Addr)) {
						ent = trx.AddEntity("netcap.InternalContact", ip.Addr)
						ent.SetType("netcap.InternalContact")
						contactType = "InternalContact"
					} else {
						ent = trx.AddEntity("netcap.ExternalContact", ip.Addr)
						ent.SetType("netcap.ExternalContact")
						contactType = "ExternalContact"
					}

					dnsNames := strings.Join(ip.DNSNames, "\n")
					ent.SetValue(ip.Addr + "\n" + ip.Geolocation + "\n" + dnsNames)
					ent.AddDisplayInformation("<h3>" + contactType + "</h3><p>" + ip.Addr + "</p><p>" + ip.Geolocation + "</p><p>" + dnsNames + "</p><p>Timestamp: " + profile.Timestamp + "</p>", "Netcap Info")

					ent.AddProperty("geolocation", "Geolocation", "strict", ip.Geolocation)
					ent.AddProperty("dnsNames", "DNS Names", "strict", dnsNames)
					ent.AddProperty("timestamp", "Timestamp", "strict", profile.Timestamp)

					ent.AddProperty("mac", "MacAddress", "strict", mac)
					ent.AddProperty("ipaddr", "IPAddress", "strict", ip.Addr)
					ent.AddProperty("path", "Path", "strict", profilesFile)
					ent.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(profile.NumPackets, 10))

					ent.SetLinkLabel(strconv.FormatInt(ip.NumPackets, 10) + " pkts\n" + humanize.Bytes(ip.Bytes))
					ent.SetLinkColor("#000000")
					ent.SetLinkThickness(maltego.GetThickness(uint64(ip.NumPackets), minPackets, maxPackets))
				}
			}
		},
	)
}
