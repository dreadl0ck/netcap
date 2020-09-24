package transform

import (
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/maltego"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
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
		inputFile = lt.Values["path"]
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
