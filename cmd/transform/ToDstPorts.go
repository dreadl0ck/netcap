package transform

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toDstPorts() {

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

	profiles := maltego.LoadIPProfiles()

	maltego.IPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string, ipaddr string) {
			if profile.MacAddr != mac {
				return
			}
			for _, ip := range profile.Contacts {
				if ip == ipaddr {
					if p, ok := profiles[ip]; ok {
						for portNum, port := range p.DstPorts {
							addDestinationPort(trx, strconv.FormatInt(int64(portNum), 10), port, min, max, p, path)
						}
					}

					break
				}
			}
			for _, ip := range profile.DeviceIPs {
				if ip == ipaddr {
					if p, ok := profiles[ip]; ok {
						for portNum, port := range p.DstPorts {
							addDestinationPort(trx, strconv.FormatInt(int64(portNum), 10), port, min, max, p, path)
						}
					}

					break
				}
			}
		},
	)
}

func addDestinationPort(trx *maltego.Transform, portStr string, port *types.Port, min, max uint64, ip *types.IPProfile, path string) {
	ent := trx.AddEntityWithPath("netcap.DestinationPort", portStr, path)

	np, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Println(err)

		np = 0
	}

	var (
		serviceName = resolvers.LookupServiceByPort(np, port.Protocol)
		di          = "<h3>Port</h3><p>Timestamp: " + utils.UnixTimeToUTC(ip.TimestampFirst) + "</p><p>ServiceName: " + serviceName + "</p>"
	)

	ent.AddDisplayInformation(di, "Netcap Info")
	ent.AddProperty("label", "Label", "strict", portStr+"\n"+serviceName)

	ent.SetLinkLabel(strconv.FormatInt(int64(port.Packets), 10) + " pkts")
	ent.SetLinkThickness(maltego.GetThickness(port.Packets, min, max))
}
