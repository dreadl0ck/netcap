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
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toContactedPorts() {
	resolverLog := zap.New(zapcore.NewNopCore())
	defer func() {
		err := resolverLog.Sync()
		if err != nil {
			log.Println(err)
		}
	}()

	resolvers.SetLogger(resolverLog)

	stdOut := os.Stdout
	os.Stdout = os.Stderr
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	netmaltego.IPProfileTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.Addr != ipaddr {
				return
			}
			for _, port := range profile.ContactedPorts {
				addContactedPort(trx, strconv.FormatInt(int64(port.PortNumber), 10), port, min, max, profile, path)
			}
		},
	)
}

func addContactedPort(trx *maltego.Transform, portStr string, port *types.Port, min uint64, max uint64, ip *types.IPProfile, path string) {
	np, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Println(err)

		np = 0
	}

	var (
		serviceName = resolvers.LookupServiceByPort(np, port.Protocol)
		di          = utils.UnixTimeToUTC(ip.TimestampFirst) + " " + ip.Addr + "<br>"
	)

	ent := addEntityWithPath(trx, "netcap.ContactedPort", portStr+"\n"+serviceName, path)
	ent.AddDisplayInformation(di, "Netcap Info")
	ent.AddProperty("label", "Label", maltego.Strict, portStr+"\n"+serviceName)
	ent.AddProperty("port", "Port", maltego.Strict, portStr)
	ent.SetLinkLabel(strconv.FormatInt(int64(port.Stats.Packets), 10) + " pkts")
	ent.SetLinkThickness(maltego.GetThickness(port.Stats.Packets, min, max))
}
