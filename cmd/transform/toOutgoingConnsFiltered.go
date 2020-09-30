package transform

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

func toOutgoingConnsFiltered() {
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
	resolvers.InitServiceDB()
	os.Stdout = stdOut

	maltego.ConnectionTransform(
		maltego.CountOutgoingConnBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ipaddr string, top12 *[]int) {
			if conn.SrcIP == ipaddr {
				name := resolvers.LookupDNSNameLocal(conn.DstIP)
				if name != "" {
					if !resolvers.IsWhitelistedDomain(name) {
						if isInTop12(conn.TotalSize, top12) {
							addConnection(trx, conn, path, min, max, maltego.InputToOutput)
						}
					}
				} else {
					if isInTop12(conn.TotalSize, top12) {
						addConnection(trx, conn, path, min, max, maltego.InputToOutput)
					}
				}
			}
		},
	)
}
