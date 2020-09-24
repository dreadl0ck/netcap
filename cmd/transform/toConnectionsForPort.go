package transform

import (
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"strconv"
	"strings"
)

func toConnectionsForPort() {

	var (
		port        string
		resolverLog = zap.New(zapcore.NewNopCore())
	)

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

	maltego.ConnectionTransform(nil, func(lt maltego.LocalTransform, trx *maltego.Transform, conn *types.Connection, min, max uint64, path string, mac string, ip string, sizes *[]int) {
		if port == "" {
			// set the port we are searching for once
			port = lt.Values["port"]
		}

		if conn.SrcPort == port || conn.DstPort == port {
			i, err := strconv.Atoi(conn.DstPort)
			if err != nil {
				return
			}
			service := resolvers.LookupServiceByPort(i, strings.ToLower(conn.TransportProto))
			addConn(trx, conn, path, min, max, service)
		}
	})
}
