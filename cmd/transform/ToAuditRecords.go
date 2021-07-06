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
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
)

var maltegoBaseConfig = collector.Config{
	WriteUnknownPackets:  false,
	Workers:              64,
	PacketBufferSize:     defaults.PacketBuffer,
	SnapLen:              defaults.SnapLen,
	Promisc:              false,
	HTTPShutdownEndpoint: true,
	NoPrompt:             true,
	Timeout:              1 * time.Second,
	DecoderConfig: &config.Config{
		Quiet:                          true,
		PrintProgress:                  true,
		Buffer:                         true,
		MemBufferSize:                  defaults.BufferSize,
		Compression:                    true,
		Proto:                          true,
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
		BannerSize:                     256,
		HarvesterBannerSize:            256,
		StreamDecoderBufSize:           100,
		StopAfterHarvesterMatch:        true,
		RemoveClosedStreams:            false,
		CompressionLevel:               defaults.CompressionLevel,
		CompressionBlockSize:           defaults.CompressionBlockSize,
		DisableGenericVersionHarvester: true,
		IgnoreDecoderInitErrors:        true,
		NumStreamWorkers:               100,
		StreamBufferSize:               100,
	},
	BaseLayer:     utils.GetBaseLayer("ethernet"),
	DecodeOptions: utils.GetDecodeOptions("lazy"),
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
		lt        = maltego.ParseLocalArguments(os.Args[3:])
		inputFile = strings.TrimPrefix(lt.Values["path"], "file://")
		trx       = &maltego.Transform{}
	)

	// check if input PCAP path is set
	if inputFile == "" {
		maltego.Die("input file path property not set", "")
	}

	io.FPrintBuildInfo(os.Stderr)
	log.Println("inputFile:", inputFile)

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	err := os.MkdirAll(outDir, defaults.DirectoryPermission)
	if err != nil {
		maltego.Die(err.Error(), "failed to create output directory")
	}

	maltegoBaseConfig.DecoderConfig.Out = outDir
	maltegoBaseConfig.DecoderConfig.Source = inputFile

	// init collector
	c := collector.New(maltegoBaseConfig)
	c.PrintConfiguration()

	// if not, use native pcapgo version
	isPcap, err := collector.IsPcap(inputFile)
	if err != nil {
		maltego.Die(err.Error(), "failed to open input file")
	}

	if isPcap {
		if err = c.CollectPcap(inputFile); err != nil {
			maltego.Die(err.Error(), "failed to collect audit records from pcap file")
		}
	} else {
		if err = c.CollectPcapNG(inputFile); err != nil {
			maltego.Die(err.Error(), "failed to collect audit records from pcapng file")
		}
	}

	writeAuditRecords(trx, outDir)
}

func writeAuditRecords(trx *maltego.Transform, outDir string) {
	files, err := ioutil.ReadDir(outDir)
	if err != nil {
		maltego.Die(err.Error(), "failed to read directory")
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
			log.Fatal("failed to count audit records:", errCount)
		}

		ent := addEntityWithPath(trx, "netcap."+name+"AuditRecords", utils.Pluralize(name), path)

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
