package transform

import (
	"github.com/dreadl0ck/netcap/io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/gopacket/pcap"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/maltego"
)

func toAuditRecordsWithDPI() {
	var (
		lt        = maltego.ParseLocalArguments(os.Args[1:])
		inputFile = strings.TrimPrefix(lt.Values["path"], "file://")
		trx       = maltego.Transform{}
	)

	// check if input PCAP path is set
	if inputFile == "" {
		die("input file path property not set", "")
	}

	io.FPrintBuildInfo(os.Stderr)
	log.Println("inputFile:", inputFile)

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	// error explicitly ignored, files will be overwritten if there are any
	err := os.MkdirAll(outDir, defaults.DirectoryPermission)
	if err != nil {
		die(err.Error(), "failed to create output directory")
	}

	maltegoBaseConfig.DecoderConfig.Out = outDir
	maltegoBaseConfig.DecoderConfig.Source = inputFile
	maltegoBaseConfig.DecoderConfig.FileStorage = filepath.Join(outDir, defaults.FileStorage)
	maltegoBaseConfig.DPI = true

	// init collector
	c := collector.New(maltegoBaseConfig)
	c.PrintConfiguration()

	// if not, use native pcapgo version
	isPcap, err := collector.IsPcap(inputFile)
	if err != nil {
		die(err.Error(), "failed to open input file")
	}

	// logic is split for both types here
	// because the pcapng reader offers ZeroCopyReadPacketData()
	if isPcap {
		if err = c.CollectPcap(inputFile); err != nil {
			log.Fatal("failed to collect audit records from pcap file: ", err)
		}
	} else {
		if err = c.CollectPcapNG(inputFile); err != nil {
			log.Fatal("failed to collect audit records from pcapng file: ", err)
		}
	}

	// open PCAP file
	r, err := pcap.OpenOffline(inputFile)
	if err != nil {
		die(err.Error(), "failed to open input file")
	}
	defer r.Close()

	writeAuditRecords(trx, outDir)
}
