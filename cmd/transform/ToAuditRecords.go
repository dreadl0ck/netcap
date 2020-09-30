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
	"github.com/dreadl0ck/gopacket/pcap"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

var maltegoBaseConfig = collector.Config{
	WriteUnknownPackets:  false,
	Workers:              1,
	PacketBufferSize:     defaults.PacketBuffer,
	SnapLen:              defaults.SnapLen,
	Promisc:              false,
	HTTPShutdownEndpoint: true,
	NoPrompt:             true,
	DecoderConfig: &decoder.Config{
		Buffer:        true,
		MemBufferSize: defaults.BufferSize,
		Compression:   true,
		Proto:         true,
		// IncludeDecoders:         strings.Join(auditRecords, ","),
		ExcludeDecoders:                "",
		Chan:                           false,
		IncludePayloads:                false,
		ExportMetrics:                  false,
		AddContext:                     true,
		FlushEvery:                     100,
		DefragIPv4:                     defaults.DefragIPv4,
		Checksum:                       defaults.Checksum,
		NoOptCheck:                     defaults.NoOptCheck,
		IgnoreFSMerr:                   defaults.IgnoreFSMErr,
		AllowMissingInit:               defaults.AllowMissingInit,
		Debug:                          true,
		HexDump:                        false,
		WaitForConnections:             true,
		WriteIncomplete:                false,
		MemProfile:                     "",
		ConnFlushInterval:              1000,
		ConnTimeOut:                    defaults.ConnTimeOut,
		FlowFlushInterval:              2000,
		FlowTimeOut:                    defaults.FlowTimeOut,
		CloseInactiveTimeOut:           defaults.CloseInactiveTimeout,
		ClosePendingTimeOut:            defaults.ClosePendingTimeout,
		FileStorage:                    defaults.FileStorage,
		CalculateEntropy:               false,
		SaveConns:                      true,
		TCPDebug:                       false,
		UseRE2:                         true,
		BannerSize:                     512,
		HarvesterBannerSize:            512,
		StreamDecoderBufSize:           0,
		StopAfterHarvesterMatch:        true,
		RemoveClosedStreams:            false,
		CompressionLevel:               defaults.CompressionLevel,
		CompressionBlockSize:           defaults.CompressionBlockSize,
		DisableGenericVersionHarvester: true,
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
		die("input file path property not set", "")
	}

	log.Println("inputFile:", inputFile)

	// redirect stdout filedescriptor to stderr
	// since all stdout get interpreted as XML from maltego
	stdout := os.Stdout
	os.Stdout = os.Stderr

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	err := os.MkdirAll(outDir, defaults.DirectoryPermission)
	if err != nil {
		die(err.Error(), "failed to create output directory")
	}

	maltegoBaseConfig.DecoderConfig.Out = outDir
	maltegoBaseConfig.DecoderConfig.Source = inputFile
	maltegoBaseConfig.DecoderConfig.FileStorage = filepath.Join(outDir, defaults.FileStorage)

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
			die(err.Error(), "failed to collect audit records from pcap file")
		}
	} else {
		if err = c.CollectPcapNG(inputFile); err != nil {
			die(err.Error(), "failed to collect audit records from pcapng file")
		}
	}

	// open PCAP file
	var r *pcap.Handle

	r, err = pcap.OpenOffline(inputFile)
	if err != nil {
		die(err.Error(), "failed to open input file")
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
		if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) {
			continue
		}

		path := filepath.Join(outDir, f.Name())
		name := strings.TrimSuffix(f.Name(), defaults.FileExtensionCompressed)

		if f.IsDir() {
			log.Println("not a file: ", err)

			continue
		}

		// TODO: return structure from collect invocation
		// that contains the number of records per type
		// to avoid opening the file again
		numRecords, errCount := io.Count(path)
		if errCount != nil {
			log.Fatal("failed to count audit records:", err)
		}

		ent := trx.AddEntityWithPath("netcap."+name+"AuditRecords", utils.Pluralize(name), path)

		ent.AddProperty("description", "Description", maltego.Strict, name+defaults.FileExtensionCompressed)
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
