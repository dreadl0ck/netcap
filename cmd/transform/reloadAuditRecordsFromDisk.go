package transform

import (
	"log"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/maltego"
)

func reloadAuditRecordsFromDisk() {
	// setup logger for io pkg
	ioLog := zap.New(zapcore.NewNopCore())
	defer func() {
		err := ioLog.Sync()
		if err != nil {
			log.Println(err)
		}
	}()

	io.SetLogger(ioLog)

	var (
		lt        = maltego.ParseLocalArguments(os.Args[1:])
		inputFile = strings.TrimPrefix(lt.Values["path"], "file://")
	)

	// check if input PCAP path is set
	if inputFile == "" {
		die("input file path property not set", "")
	}

	log.Println("inputFile:", inputFile)

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	log.Println("path:", outDir, "iface", lt.Value)
	writeLiveAuditRecords(outDir)
}
