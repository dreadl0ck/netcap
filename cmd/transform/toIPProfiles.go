package transform

import (
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toIPProfiles() {
	maltego.IPProfileTransform(maltego.CountIPPackets, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string) {
		addIPProfile(trx, profile, path, min, max)
	})
}

func addIPProfile(trx *maltego.Transform, profile *types.IPProfile, path string, min, max uint64) {
	ident := profile.Addr + "\n" + profile.Geolocation
	ent := trx.AddEntityWithPath("netcap.IPProfile", ident, path)

	ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
	ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
	ent.AddProperty("ipaddr", "IPAddr", maltego.Strict, profile.Addr)
	ent.AddDisplayInformation(strings.Join(profile.Applications, "<br>"), "Applications")
	ent.AddDisplayInformation(strings.Join(profile.DNSNames, "<br>"), "DNS Names")
	ent.AddDisplayInformation(createJa3TableHTML(profile.Ja3), "JA3")
	ent.AddDisplayInformation(createSNITableHTML(profile.SNIs), "SNIs")
	ent.AddDisplayInformation(createProtocolsTableHTML(profile.Protocols), "Protocols")
	ent.AddDisplayInformation(createPortsTableHTML(profile.SrcPorts), "Source Ports")
	ent.AddDisplayInformation(createPortsTableHTML(profile.DstPorts), "Destination Ports")
}
