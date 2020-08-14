/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/gopacket/pcap"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

var maltegoBaseConfig = collector.Config{
	WriteUnknownPackets: false,
	Workers:             runtime.NumCPU(),
	PacketBufferSize:    netcap.DefaultPacketBuffer,
	SnapLen:             1514, // TODO: make configurable within Maltego, add as property for pcap?
	Promisc:             false,
	DecoderConfig: &decoder.Config{
		Buffer:        true,
		MemBufferSize: netcap.DefaultBufferSize,
		Compression:   true,
		CSV:           false,
		// IncludeDecoders:         strings.Join(auditRecords, ","),
		ExcludeDecoders:         "",
		WriteChan:               false,
		IncludePayloads:         false,
		Export:                  false,
		AddContext:              true,
		FlushEvery:              100,
		DefragIPv4:              netcap.DefaultDefragIPv4,
		Checksum:                netcap.DefaultChecksum,
		NoOptCheck:              netcap.DefaultNoOptCheck,
		IgnoreFSMerr:            netcap.DefaultIgnoreFSMErr,
		AllowMissingInit:        netcap.DefaultAllowMissingInit,
		Debug:                   false,
		HexDump:                 false,
		WaitForConnections:      true,
		WriteIncomplete:         false,
		MemProfile:              "",
		ConnFlushInterval:       1000,
		ConnTimeOut:             10 * time.Second,
		FlowFlushInterval:       2000,
		FlowTimeOut:             10 * time.Second,
		CloseInactiveTimeOut:    24 * time.Hour,
		ClosePendingTimeOut:     5 * time.Second,
		FileStorage:             netcap.DefaultFileStorage,
		CalculateEntropy:        false,
		SaveConns:               false,
		TCPDebug:                false,
		UseRE2:                  true,
		BannerSize:              512,
		HarvesterBannerSize:     512,
		StreamDecoderBufSize:    0,
		StopAfterHarvesterMatch: true,
	},
	BaseLayer:     utils.GetBaseLayer("ethernet"),
	DecodeOptions: utils.GetDecodeOptions("datagrams"),
	Quiet:         true,
	DPI:           false,
	ResolverConfig: resolvers.Config{
		ReverseDNS:    false,
		LocalDNS:      true,
		MACDB:         true,
		Ja3DB:         true,
		ServiceDB:     true,
		GeolocationDB: true,
	},
	OutDirPermission:      0o700,
	FreeOSMem:             0,
	ReassembleConnections: true,
}

func toAuditRecords() {
	var (
		lt        = maltego.ParseLocalArguments(os.Args[1:])
		inputFile = lt.Values["path"]
		trx       = maltego.Transform{}
	)

	// check if input PCAP path is set
	if inputFile == "" {
		trx.AddUIMessage("Input file path property not set!", maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		log.Println("input file path property not set")

		return
	}

	// check if input PCAP path exists
	//inputStat, err := os.Stat(inputFile)
	//if err != nil {
	//	trx.AddUIMessage("Input file path does not exist! error: "+err.Error(), maltego.UIM_FATAL)
	//	fmt.Println(trx.ReturnOutput())
	//	log.Println("input file path does not exist", err)
	//	return
	//}

	log.Println("inputFile:", inputFile)

	// redirect stdout filedescriptor to stderr
	// since all stdout get interpreted as XML from maltego
	stdout := os.Stdout
	os.Stdout = os.Stderr

	// create storage path for audit records
	// start := time.Now()

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	err := os.MkdirAll(outDir, outDirPermission)
	if err != nil {
		log.Println(err)
	}

	maltegoBaseConfig.DecoderConfig.Out = outDir
	maltegoBaseConfig.DecoderConfig.Source = inputFile
	maltegoBaseConfig.DecoderConfig.FileStorage = filepath.Join(outDir, netcap.DefaultFileStorage)

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
	var r *pcap.Handle

	r, err = pcap.OpenOffline(inputFile)
	if err != nil {
		log.Fatal(err)
	}

	defer r.Close()

	// restore stdout
	os.Stdout = stdout

	writeAuditRecords(trx, outDir)
}

func writeAuditRecords(trx maltego.Transform, outDir string) {
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".ncap.gz") {
			continue
		}

		ident := filepath.Join(outDir, f.Name())
		name := strings.TrimSuffix(f.Name(), ".ncap.gz")
		//
		//// stat generated profiles
		//stat, err := os.Stat(ident)
		//if err != nil {
		//	utils.DebugLog.Println("invalid path: ", err)
		//	continue
		//}
		if f.IsDir() {
			utils.DebugLog.Println("not a file: ", err)

			continue
		}

		// TODO: return structure from collect invocation
		// that contains the number of records per type
		// to avoid opening the file again
		numRecords, errCount := netcap.Count(ident)
		if errCount != nil {
			log.Fatal("failed to count audit records:", err)
		}

		ent := trx.AddEntity("netcap."+name+"AuditRecords", utils.Pluralize(name))

		ent.AddProperty("path", "Path", "strict", ident)
		ent.AddProperty("description", "Description", "strict", name+".ncap.gz")

		ent.SetLinkLabel(strconv.Itoa(int(numRecords)))

		// add notes for specific audit records here
		switch name {
		// case "DeviceProfile":
		//	di := "<h3>Device Profile</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
		//	ent.AddDisplayInformation(di, "Netcap Info")
		//	ent.SetNote("Storage Path: " + outDir + "\nInput File Size: " + humanize.Bytes(uint64(inputSize)) + "\nOutput File Size: " + humanize.Bytes(uint64(f.Size())) + "\nNum Profiles: " + strconv.FormatInt(netcap.Count(ident), 10) + "\nSource File: " + inputFile + "\nLink Type: " + r.LinkType().String() + "\nParsing Time: " + time.Since(start).String())
		}
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
