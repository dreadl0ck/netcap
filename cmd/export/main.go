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

package export

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"

	"github.com/evilsocket/islazy/tui"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/metrics"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
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
		io.GenerateConfig(fs, "export")

		return
	}

	if *flagListInterfaces {
		utils.ListAllNetworkInterfaces()

		return
	}

	// set data source
	var source string
	switch {
	case *flagInput != "":
		source = *flagInput
	case *flagInterface != "":
		source = *flagInterface
	default:
		source = "unknown"
	}

	// register metrics
	for _, m := range types.Metrics {
		prometheus.MustRegister(m)
	}

	switch {
	case filepath.Ext(*flagInput) == defaults.FileExtension || filepath.Ext(*flagInput) == ".gz":
		metrics.ServeMetricsAt(*flagMetricsAddress, nil)
		exportFile(*flagInput)
	case *flagDir != "":
		metrics.ServeMetricsAt(*flagMetricsAddress, nil)
		exportDir(*flagDir)
	case *flagInput != "" || *flagInterface != "":
		if *flagReplay {
			log.Fatal("replay flag is set, but replaying the audit records is only possible when exporting audit records.")
		}

		if *flagInput != "" {
			// stat file
			stat, errStat := os.Stat(*flagInput)
			if errStat != nil {
				log.Fatal("failed to stat input:", errStat)
			}

			// check if its a directory
			if stat.IsDir() {
				exportDir(*flagInput)

				break
			}
		}

		// it's a file
		// parse PCAP file or live from interface
		// init collector
		c := collector.New(collector.Config{
			WriteUnknownPackets: !*flagIngoreUnknown,
			Workers:             *flagWorkers,
			PacketBufferSize:    *flagPacketBuffer,
			SnapLen:             *flagSnapLen,
			Promisc:             *flagPromiscMode,
			LogErrors:           *flagLogErrors,
			DecoderConfig: &config.Config{
				Buffer:               *flagBuffer,
				Compression:          *flagCompress,
				CSV:                  *flagCSV,
				IncludeDecoders:      *flagInclude,
				ExcludeDecoders:      *flagExclude,
				Out:                  *flagOutDir,
				Source:               source,
				IncludePayloads:      *flagPayload,
				ExportMetrics:        true,
				AddContext:           *flagContext,
				MemBufferSize:        *flagMemBufferSize,
				FlushEvery:           *flagFlushevery,
				DefragIPv4:           *flagDefragIPv4,
				Checksum:             *flagChecksum,
				NoOptCheck:           *flagNooptcheck,
				IgnoreFSMerr:         *flagIgnorefsmerr,
				AllowMissingInit:     *flagAllowmissinginit,
				Debug:                *flagDebug,
				HexDump:              *flagHexdump,
				WaitForConnections:   *flagWaitForConnections,
				WriteIncomplete:      *flagWriteincomplete,
				MemProfile:           *flagMemprofile,
				ConnFlushInterval:    *flagConnFlushInterval,
				ConnTimeOut:          *flagConnTimeOut,
				FlowFlushInterval:    *flagFlowFlushInterval,
				FlowTimeOut:          *flagFlowTimeOut,
				CloseInactiveTimeOut: *flagCloseInactiveTimeout,
				ClosePendingTimeOut:  *flagClosePendingTimeout,
				FileStorage:          *flagFileStorage,
				CalculateEntropy:     *flagCalcEntropy,
				Quiet:                false,
				PrintProgress:        false,
			},
			BaseLayer:     utils.GetBaseLayer(*flagBaseLayer),
			DecodeOptions: utils.GetDecodeOptions(*flagDecodeOptions),
			// FileStorage:   defaults.FileStorage, // TODO:
			DPI: *flagDPI,
			ResolverConfig: resolvers.Config{
				ReverseDNS:    *flagReverseDNS,
				LocalDNS:      *flagLocalDNS,
				MACDB:         *flagMACDB,
				Ja3DB:         *flagJa3DB,
				ServiceDB:     *flagServiceDB,
				GeolocationDB: *flagGeolocationDB,
			},
			OutDirPermission:      0o700,
			FreeOSMem:             0,
			ReassembleConnections: true,
		})

		metrics.ServeMetricsAt(*flagMetricsAddress, c)

		io.PrintLogo()

		// print configuration as table
		tui.Table(os.Stdout, []string{"Setting", "Value"}, [][]string{
			{"Workers", strconv.Itoa(*flagWorkers)},
			{"MemBuffer", strconv.FormatBool(*flagBuffer)},
			{"Compression", strconv.FormatBool(*flagCompress)},
			{"PacketBuffer", strconv.Itoa(*flagPacketBuffer)},
		})
		fmt.Println() // add a newline

		// collect traffic live from named interface
		if *flagInterface != "" {
			err = c.CollectLive(*flagInterface, *flagBPF, context.Background())
			if err != nil {
				log.Fatal("failed to collect live packets: ", err)
			}

			return
		}

		// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
		// setting BPF filters is not yet supported by the pcapgo package
		if *flagBPF != "" {
			if err = c.CollectBPF(*flagInput, *flagBPF); err != nil {
				log.Fatal("failed to set BPF: ", err)
			}

			return
		}

		// if not, use native pcapgo version
		isPcap, errCheck := collector.IsPcap(*flagInput)
		if errCheck != nil {
			// invalid path
			fmt.Println("failed to open file:", errCheck)
			os.Exit(1)
		}

		if isPcap {
			if err = c.CollectPcap(*flagInput); err != nil {
				log.Fatal("failed to collect audit records from pcap file: ", err)
			}
		} else {
			if err = c.CollectPcapNG(*flagInput); err != nil {
				log.Fatal("failed to collect audit records from pcapng file: ", err)
			}
		}

		// memory profiling
		if *flagMemProfile {
			f, errProfile := os.Create("netcap-" + netcap.Version + ".mem.profile")
			if errProfile != nil {
				log.Fatal("failed create memory profile: ", errProfile)
			}

			if err = pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("failed to write heap profile: ", err)
			}

			err = f.Close()
			if err != nil {
				panic("failed to write memory profile: " + err.Error())
			}
		}
	default:
		log.Fatal("nothing to do.")
	}

	// wait until the end of time
	<-make(chan bool)
}
