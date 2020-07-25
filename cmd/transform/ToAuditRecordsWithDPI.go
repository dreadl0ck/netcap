package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/pcap"
	"github.com/dreadl0ck/netcap/collector"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"path/filepath"
	"time"
)

func ToAuditRecordsWithDPI() {

	var (
		lt        = maltego.ParseLocalArguments(os.Args[1:])
		inputFile = lt.Values["path"]
		trx       = maltego.MaltegoTransform{}
	)

	// check if input PCAP path is set
	if inputFile == "" {
		trx.AddUIMessage("Input file path property not set!", maltego.UIM_FATAL)
		fmt.Println(trx.ReturnOutput())
		log.Fatal("input file path property not set")
	}

	// check if input PCAP path exists
	inputStat, err := os.Stat(inputFile)
	if err != nil {
		trx.AddUIMessage("Input file path does not exist! error: "+err.Error(), maltego.UIM_FATAL)
		fmt.Println(trx.ReturnOutput())
		log.Fatal("input file path does not exist", err)
	}

	log.Println("inputFile:", inputFile)

	// redirect stdout filedescriptor to stderr
	// since all stdout get interpreted as XML from maltego
	stdout := os.Stdout
	os.Stdout = os.Stderr

	// create storage path for audit records
	start := time.Now()

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	// error explicitly ignored, files will be overwritten if there are any
	os.MkdirAll(outDir, outDirPermission)

	maltegoBaseConfig.DecoderConfig.Out = outDir
	maltegoBaseConfig.DecoderConfig.Source = inputFile
	maltegoBaseConfig.DecoderConfig.FileStorage = filepath.Join(outDir, "files")
	maltegoBaseConfig.DPI = true

	// init collector
	c := collector.New(maltegoBaseConfig)
	c.PrintConfiguration()

	// if not, use native pcapgo version
	isPcap, err := collector.IsPcap(inputFile)
	if err != nil {
		// invalid path
		fmt.Println("failed to open file:", err)
		os.Exit(1)
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
		log.Fatal(err)
	}
	defer r.Close()

	// restore stdout
	os.Stdout = stdout

	writeAuditRecords(trx, inputStat.Size(), outDir, inputFile, r, start)
}
