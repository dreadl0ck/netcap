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

func toIncomingConnsFiltered() {
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
		maltego.CountIncomingConnBytesFiltered,
		func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ipaddr string, top12 *[]int) {
			if conn.DstIP == ipaddr {
				name := resolvers.LookupDNSNameLocal(conn.SrcIP)
				if name != "" {
					if !resolvers.IsWhitelistedDomain(name) {
						if isInTop12(conn.TotalSize, top12) {
							addConnection(trx, conn, path, min, max, maltego.OutputToInput)
						}
					}
				} else {
					if isInTop12(conn.TotalSize, top12) {
						addConnection(trx, conn, path, min, max, maltego.OutputToInput)
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
