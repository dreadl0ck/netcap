package transform

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dustin/go-humanize"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

func toIncomingFlowsFiltered() {
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
	resolvers.InitLocalDNS()
	resolvers.InitDNSWhitelist()
	os.Stdout = stdOut

	maltego.ConnectionTransform(
		maltego.CountIncomingConnBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ipaddr string, top12 *[]int) {
			if conn.DstIP == ipaddr {
				name := resolvers.LookupDNSNameLocal(conn.SrcIP)
				if name != "" {
					if !resolvers.IsWhitelistedDomain(name) {
						if isInTop12(conn.TotalSize, top12) {
							addInConn(trx, conn, min, max, name, path)
						}
					}
				} else {
					if isInTop12(conn.TotalSize, top12) {
						addInConn(trx, conn, min, max, conn.SrcIP, path)
					}
				}
			}
		},
	)
}

func isInTop12(val int32, sizes *[]int) bool {
	for _, s := range *sizes {
		if s == int(val) {
			return true
		}
	}
	return false
}

func addInConn(trx *maltego.Transform, conn *types.Connection, min, max uint64, name string, path string) {
	ent := trx.AddEntityWithPath("netcap.Flow", conn.UID+"\n"+name, path)

	di := "<h3>Incoming Flow: " + conn.SrcIP + ":" + conn.SrcPort + " -> " + conn.DstIP + ":" + conn.DstPort + "</h3><p>Timestamp: " + utils.UnixTimeToUTC(conn.TimestampFirst) + "</p><p>TimestampLast: " + utils.UnixTimeToUTC(conn.TimestampLast) + "</p><p>Duration: " + fmt.Sprint(time.Duration(conn.Duration)) + "</p><p>TotalSize: " + humanize.Bytes(uint64(conn.TotalSize)) + "</p>"
	ent.AddDisplayInformation(di, "Netcap Info")

	ent.SetLinkDirection(maltego.OutputToInput)
	ent.SetLinkLabel(humanize.Bytes(uint64(conn.TotalSize)))
	ent.SetLinkThickness(maltego.GetThickness(uint64(conn.TotalSize), min, max))
}
