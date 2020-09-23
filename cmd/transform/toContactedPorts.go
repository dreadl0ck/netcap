package transform

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/maltego"
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

	maltego.IPProfileTransform(
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
		di          = "<h3>Port</h3><p>Timestamp: " + utils.UnixTimeToUTC(ip.TimestampFirst) + "</p><p>ServiceName: " + serviceName + "</p>"
	)

	ent := trx.AddEntityWithPath("netcap.ContactedPort", portStr+"\n"+serviceName, path)
	ent.AddDisplayInformation(di, "Netcap Info")
	ent.AddProperty("label", "Label", maltego.Strict, portStr+"\n"+serviceName)

	ent.SetLinkLabel(strconv.FormatInt(int64(port.Packets), 10) + " pkts")
	ent.SetLinkThickness(maltego.GetThickness(port.Packets, min, max))
}
