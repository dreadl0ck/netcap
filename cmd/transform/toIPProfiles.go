/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"net"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

func toIPProfiles() {
	netmaltego.IPProfileTransform(netmaltego.CountIPPackets, func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string) {
		addIPProfile(trx, profile, path, min, max)
	})
}

func addIPProfile(trx *maltego.Transform, profile *types.IPProfile, path string, min, max uint64) {
	ident := profile.Addr + "\n" + profile.Geolocation

	var ent *maltego.Entity
	if resolvers.IsPrivateIP(net.ParseIP(profile.Addr)) {
		ent = addEntityWithPath(trx, "netcap.InternalIPProfile", ident, path)
	} else {
		ent = addEntityWithPath(trx, "netcap.ExternalIPProfile", ident, path)
	}

	ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
	ent.SetLinkThickness(maltego.GetThickness(uint64(profile.NumPackets), min, max))
	ent.AddProperty(netmaltego.PropertyIpAddr, "IPAddr", maltego.Strict, profile.Addr)
	ent.AddDisplayInformation(strings.Join(profile.Applications, "<br>"), "Applications")
	ent.AddDisplayInformation(strings.Join(profile.DNSNames, "<br>"), "DNS Names")
	ent.AddDisplayInformation(createJa3TableHTML(profile.Ja3Hashes), "Ja3Hashes")
	ent.AddDisplayInformation(createSNITableHTML(profile.SNIs), "SNIs")
	ent.AddDisplayInformation(createProtocolsTableHTML(profile.Protocols), "Protocols")
	ent.AddDisplayInformation(createPortsTableHTML(profile.SrcPorts), "Source Ports")
	ent.AddDisplayInformation(createPortsTableHTML(profile.DstPorts), "Destination Ports")
	ent.AddDisplayInformation(createPortsTableHTML(profile.ContactedPorts), "Contacted Ports")
}
