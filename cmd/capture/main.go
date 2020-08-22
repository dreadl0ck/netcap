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

package capture

import (
	"fmt"
	"github.com/mgutz/ansi"
	"log"
	"net/http"

	// _ "net/http/pprof"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/dustin/go-humanize"
	"github.com/felixge/fgprof"
)

// Run parses the subcommand flags and handles the arguments.
func Run() {
	// parse commandline flags
	fs.Usage = printUsage

	err := fs.Parse(os.Args[2:])
	if err != nil {
		log.Fatal(err)
	}

	if *flagGenerateConfig {
		netcap.GenerateConfig(fs, "capture")

		return
	}

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	// print a markdown overview of all available decoders and fields
	if *flagPrintProtocolOverview {
		decoder.MarkdownOverview()

		return
	}

	if *flagListInterfaces {
		utils.ListAllNetworkInterfaces()

		return
	}

	// configure CPU profiling
	if *flagCPUProfile {
		defer func() func() {
			if *flagCPUProfile {
				f, errCPUProfile := os.Create("netcap-" + netcap.Version + ".cpu.profile")
				if errCPUProfile != nil {
					log.Fatalf("could not open cpu profile file %q, error: %s\n", "netcap.cpu.profile", errCPUProfile)
				}

				if errCPUProfile = pprof.StartCPUProfile(f); errCPUProfile != nil {
					log.Fatalf("failed to start CPU profiling, error: %s\n", errCPUProfile)
				}

				return func() {
					pprof.StopCPUProfile()

					errCPUProfile = f.Close()
					if errCPUProfile != nil {
						panic("failed to write CPU profile: " + errCPUProfile.Error())
					}
				}
			}

			return func() {}
		}()

		// fgprof allows to analyze On-CPU as well as Off-CPU (e.g. I/O) time
		http.DefaultServeMux.Handle("/debug/fgprof", fgprof.Handler())

		go func() {
			log.Println(http.ListenAndServe(":6060", nil))
		}()
	}

	// print decoders and exit
	if *flagDecoders {
		decoder.ShowDecoders(true)

		return
	}

	// live mode?
	var live bool
	if *flagInterface != "" {
		live = true
	}

	// set data source
	var source string
	if *flagInput != "" {
		source = *flagInput
	} else if *flagInterface != "" {
		source = *flagInterface
	} else {
		source = "unknown"
	}

	if *flagReassemblyDebug {
		reassembly.Debug = true
	}

	var elasticAddrs []string
	if *flagElasticAddrs != "" {
		elasticAddrs = strings.Split(*flagElasticAddrs, ",")
	}

	if *flagGenerateElasticIndices {
		generateElasticIndices(elasticAddrs)

		return
	}

	// abort if there is no input or no live capture
	if *flagInput == "" && !live {
		printHeader()
		fmt.Println(ansi.Red + "> nothing to do. need a pcap file with the read flag (-read) or live mode and an interface (-iface)" + ansi.Reset)
		os.Exit(1)
	}

	if strings.HasSuffix(*flagInput, ".ncap.gz") || strings.HasSuffix(*flagInput, ".ncap") {
		printHeader()
		fmt.Println(ansi.Red + "> the capture tool is used to create audit records from live traffic or a pcap dumpfile" + ansi.Reset)
		fmt.Println(ansi.Red + "> use the dump tool to read netcap audit records" + ansi.Reset)
		os.Exit(1)
	}

	// init collector
	c := collector.New(collector.Config{
		Workers:               *flagWorkers,
		PacketBufferSize:      *flagPacketBuffer,
		WriteUnknownPackets:   !*flagIgnoreUnknown,
		Promisc:               *flagPromiscMode,
		SnapLen:               *flagSnapLen,
		BaseLayer:             utils.GetBaseLayer(*flagBaseLayer),
		DecodeOptions:         utils.GetDecodeOptions(*flagDecodeOptions),
		Quiet:                 *flagQuiet,
		DPI:                   *flagDPI,
		ReassembleConnections: *flagReassembleConnections,
		FreeOSMem:             *flagFreeOSMemory,
		LogErrors:             *flagLogErrors,
		DecoderConfig: &decoder.Config{
			Buffer:        *flagBuffer,
			MemBufferSize: *flagMemBufferSize,
			Compression:   *flagCompress,
			CSV:           *flagCSV,
			Null:          *flagNull,
			Elastic:       *flagElastic,
			ElasticConfig: netcap.ElasticConfig{
				ElasticAddrs:   elasticAddrs,
				ElasticUser:    *flagElasticUser,
				ElasticPass:    *flagElasticPass,
				KibanaEndpoint: *flagKibanaEndpoint,
			},
			BulkSizeGoPacket:        *flagBulkSizeGoPacket,
			BulkSizeCustom:          *flagBulkSizeCustom,
			IncludeDecoders:         *flagInclude,
			ExcludeDecoders:         *flagExclude,
			Out:                     *flagOutDir,
			Proto:                   *flagProto,
			JSON:                    *flagJSON,
			Chan:                    false,
			Source:                  source,
			IncludePayloads:         *flagPayload,
			ExportMetrics:           false,
			AddContext:              *flagContext,
			FlushEvery:              *flagFlushevery,
			DefragIPv4:              *flagDefragIPv4,
			Checksum:                *flagChecksum,
			NoOptCheck:              *flagNooptcheck,
			IgnoreFSMerr:            *flagIgnorefsmerr,
			AllowMissingInit:        *flagAllowmissinginit,
			Debug:                   *flagDebug,
			HexDump:                 *flagHexdump,
			WaitForConnections:      *flagWaitForConnections,
			WriteIncomplete:         *flagWriteincomplete,
			MemProfile:              *flagMemprofile,
			ConnFlushInterval:       *flagConnFlushInterval,
			ConnTimeOut:             *flagConnTimeOut,
			FlowFlushInterval:       *flagFlowFlushInterval,
			FlowTimeOut:             *flagFlowTimeOut,
			CloseInactiveTimeOut:    *flagCloseInactiveTimeout,
			ClosePendingTimeOut:     *flagClosePendingTimeout,
			FileStorage:             *flagFileStorage,
			CalculateEntropy:        *flagCalcEntropy,
			SaveConns:               *flagSaveConns,
			TCPDebug:                *flagTCPDebug,
			UseRE2:                  *flagUseRE2,
			BannerSize:              *flagBannerSize,
			StreamDecoderBufSize:    *flagStreamDecoderBufSize,
			HarvesterBannerSize:     *flagHarvesterBannerSize,
			StopAfterHarvesterMatch: *flagStopAfterHarvesterMatch,
			CustomRegex:             *flagCustomCredsRegex,
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:    *flagReverseDNS,
			LocalDNS:      *flagLocalDNS,
			MACDB:         *flagMACDB,
			Ja3DB:         *flagJa3DB,
			ServiceDB:     *flagServiceDB,
			GeolocationDB: *flagGeolocationDB,
		},
	})

	c.PrintConfiguration()

	// collect traffic live from named interface
	if live {
		err = c.CollectLive(*flagInterface, *flagBPF)
		if err != nil {
			log.Fatal("failed to collect live packets: ", err)
		}

		return
	}

	// start timer
	start := time.Now()

	// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
	// setting BPF filters is not yet supported by the pcapgo package
	if *flagBPF != "" {
		if err = c.CollectBPF(*flagInput, *flagBPF); err != nil {
			log.Fatal("failed to set BPF: ", err)
		}

		return
	}

	// if not, use native pcapgo version
	isPcap, err := collector.IsPcap(*flagInput)
	if err != nil {
		// invalid path
		fmt.Println("failed to open file:", err)
		os.Exit(1)
	}

	// logic is split for both types here
	// because the pcapng reader offers ZeroCopyReadPacketData()
	if isPcap {
		if err = c.CollectPcap(*flagInput); err != nil {
			log.Fatal("failed to collect audit records from pcap file: ", err)
		}
	} else {
		if err = c.CollectPcapNG(*flagInput); err != nil {
			log.Fatal("failed to collect audit records from pcapng file: ", err)
		}
	}

	if *flagTime {
		// stat input file
		stat, _ := os.Stat(*flagInput)
		fmt.Println("size", humanize.Bytes(uint64(stat.Size())), "done in", time.Since(start))
	}

	// memory profiling
	if *flagMemProfile {
		f, errProfile := os.Create("netcap-" + netcap.Version + ".mem.profile")
		if errProfile != nil {
			log.Fatal("failed create memory profile: ", errProfile)
		}

		if errProfile = pprof.WriteHeapProfile(f); errProfile != nil {
			log.Fatal("failed to write heap profile: ", errProfile)
		}

		err = f.Close()
		if err != nil {
			panic("failed to write memory profile: " + err.Error())
		}
	}
}

func generateElasticIndices(elasticAddrs []string) {
	decoder.ApplyActionToCustomDecoders(func(d decoder.CustomDecoderAPI) {
		netcap.CreateElasticIndex(&netcap.WriterConfig{
			CSV:     *flagCSV,
			Proto:   *flagProto,
			JSON:    *flagJSON,
			Name:    d.GetName(),
			Null:    *flagNull,
			Elastic: *flagElastic,
			ElasticConfig: netcap.ElasticConfig{
				ElasticAddrs:   elasticAddrs,
				ElasticUser:    *flagElasticUser,
				ElasticPass:    *flagElasticPass,
				KibanaEndpoint: *flagKibanaEndpoint,
				BulkSize:       *flagBulkSizeCustom,
			},
			Buffer:           *flagBuffer,
			Compress:         *flagCompress,
			Out:              *flagOutDir,
			Chan:             false,
			ChanSize:         0,
			MemBufferSize:    *flagMemBufferSize,
			Version:          netcap.Version,
			StartTime:        time.Now(),
		})
	})

	decoder.ApplyActionToGoPacketDecoders(func(d *decoder.GoPacketDecoder) {
		netcap.CreateElasticIndex(&netcap.WriterConfig{
			CSV:     *flagCSV,
			Proto:   *flagProto,
			JSON:    *flagJSON,
			Name:    d.Layer.String(),
			Null:    *flagNull,
			Elastic: *flagElastic,
			ElasticConfig: netcap.ElasticConfig{
				ElasticAddrs:   elasticAddrs,
				ElasticUser:    *flagElasticUser,
				ElasticPass:    *flagElasticPass,
				KibanaEndpoint: *flagKibanaEndpoint,
				BulkSize:       *flagBulkSizeCustom,
			},
			Buffer:           *flagBuffer,
			Compress:         *flagCompress,
			Out:              *flagOutDir,
			Chan:             false,
			ChanSize:         0,
			MemBufferSize:    *flagMemBufferSize,
			Version:          netcap.Version,
			StartTime:        time.Now(),
		})
	})
}