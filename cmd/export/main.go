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
	"github.com/urfave/cli/v3"

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
// This is a compatibility wrapper for the old Run() interface.
func Run() {
	// Remove date/time from log output to prevent duplicate timestamps
	// when running in Docker/systemd (which add their own timestamps)
	log.SetFlags(0)

	// Create a new CLI app just for parsing flags
	cmd := &cli.Command{
		Name:  "export",
		Usage: "export audit records",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the export command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-config") {
		// TODO: Update GenerateConfig to work with urfave/cli
		fmt.Println("gen-config not yet implemented with urfave/cli")
		return nil
	}

	if c.Bool("interfaces") {
		utils.ListAllNetworkInterfaces()
		return nil
	}

	flagInput := c.String("read")
	flagInterface := c.String("iface")
	flagDir := c.String("dir")

	// set data source
	var source string
	switch {
	case flagInput != "":
		source = flagInput
	case flagInterface != "":
		source = flagInterface
	default:
		source = "unknown"
	}

	// register metrics
	for _, m := range types.Metrics {
		prometheus.MustRegister(m)
	}

	flagMetricsAddress := c.String("address")
	
	// Set helper variables for utility functions
	currentMemBufferSize = c.Int("membuf-size")
	currentReplayMode = c.Bool("replay")
	currentDumpJSON = c.Bool("dumpJson")

	switch {
	case filepath.Ext(flagInput) == defaults.FileExtension || filepath.Ext(flagInput) == ".gz":
		metrics.ServeMetricsAt(flagMetricsAddress, nil)
		exportFile(flagInput)
	case flagDir != "":
		metrics.ServeMetricsAt(flagMetricsAddress, nil)
		exportDir(flagDir)
	case flagInput != "" || flagInterface != "":
		if c.Bool("replay") {
			log.Fatal("replay flag is set, but replaying the audit records is only possible when exporting audit records.")
		}

		if flagInput != "" {
			// stat file
			stat, errStat := os.Stat(flagInput)
			if errStat != nil {
				log.Fatal("failed to stat input:", errStat)
			}

			// check if its a directory
			if stat.IsDir() {
				exportDir(flagInput)
				return nil
			}
		}

		// it's a file
		// parse PCAP file or live from interface
		// init collector
		coll := collector.New(collector.Config{
			WriteUnknownPackets: !c.Bool("ignore-unknown"),
			Workers:             c.Int("workers"),
			PacketBufferSize:    c.Int("pbuf"),
			SnapLen:             c.Int("snaplen"),
			Promisc:             c.Bool("promisc"),
			LogErrors:           c.Bool("log-errors"),
			DecoderConfig: &config.Config{
				Buffer:               c.Bool("buf"),
				Compression:          c.Bool("compress"),
				CSV:                  c.Bool("csv"),
				IncludeDecoders:      c.String("include"),
				ExcludeDecoders:      c.String("exclude"),
				Out:                  c.String("out"),
				Source:               source,
				IncludePayloads:      c.Bool("payload"),
				ExportMetrics:        true,
				AddContext:           c.Bool("context"),
				MemBufferSize:        c.Int("membuf-size"),
				FlushEvery:           c.Int("flushevery"),
				DefragIPv4:           c.Bool("ip4defrag"),
				Checksum:             c.Bool("checksum"),
				NoOptCheck:           c.Bool("nooptcheck"),
				IgnoreFSMerr:         c.Bool("ignorefsmerr"),
				AllowMissingInit:     c.Bool("allowmissinginit"),
				Debug:                c.Bool("debug"),
				HexDump:              c.Bool("hexdump"),
				WaitForConnections:   c.Bool("wait-conns"),
				WriteIncomplete:      c.Bool("writeincomplete"),
				MemProfile:           c.String("memprofile"),
				ConnFlushInterval:    c.Int("conn-flush-interval"),
				ConnTimeOut:          c.Duration("conn-timeout"),
				FlowFlushInterval:    c.Int("flow-flush-interval"),
				FlowTimeOut:          c.Duration("flow-timeout"),
				CloseInactiveTimeOut: c.Duration("close-inactive-timeout"),
				ClosePendingTimeOut:  c.Duration("close-pending-timeout"),
				FileStorage:          c.String("fileStorage"),
				CalculateEntropy:     c.Bool("entropy"),
				Quiet:                false,
				PrintProgress:        false,
			},
			BaseLayer:     utils.GetBaseLayer(c.String("base")),
			DecodeOptions: utils.GetDecodeOptions(c.String("opts")),
			// FileStorage:   defaults.FileStorage, // TODO:
			DPI:        c.Bool("dpi"),
			DPIModules: c.String("dpi-modules"),
			ResolverConfig: resolvers.Config{
				ReverseDNS:    c.Bool("reverse-dns"),
				LocalDNS:      c.Bool("local-dns"),
				MACDB:         c.Bool("macDB"),
				Ja3DB:         c.Bool("ja3DB"),
				ServiceDB:     c.Bool("serviceDB"),
				GeolocationDB: c.Bool("geoDB"),
			},
			OutDirPermission:      0o700,
			FreeOSMem:             0,
			ReassembleConnections: true,
		})

		metrics.ServeMetricsAt(flagMetricsAddress, coll)

		io.PrintLogo()

		// print configuration as table
		tui.Table(os.Stdout, []string{"Setting", "Value"}, [][]string{
			{"Workers", strconv.Itoa(c.Int("workers"))},
			{"MemBuffer", strconv.FormatBool(c.Bool("buf"))},
			{"Compression", strconv.FormatBool(c.Bool("compress"))},
			{"PacketBuffer", strconv.Itoa(c.Int("pbuf"))},
		})
		fmt.Println() // add a newline

		flagBPF := c.String("bpf")

		// collect traffic live from named interface
		if flagInterface != "" {
			err := coll.CollectLive(flagInterface, flagBPF, context.Background())
			if err != nil {
				log.Fatal("failed to collect live packets: ", err)
			}

			return nil
		}

		// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
		// setting BPF filters is not yet supported by the pcapgo package
		if flagBPF != "" {
			if err := coll.CollectBPF(flagInput, flagBPF); err != nil {
				log.Fatal("failed to set BPF: ", err)
			}

			return nil
		}

		// if not, use native pcapgo version
		isPcap, errCheck := collector.IsPcap(flagInput)
		if errCheck != nil {
			// invalid path
			fmt.Println("failed to open file:", errCheck)
			os.Exit(1)
		}

		if isPcap {
			if err := coll.CollectPcap(flagInput); err != nil {
				log.Fatal("failed to collect audit records from pcap file: ", err)
			}
		} else {
			if err := coll.CollectPcapNG(flagInput); err != nil {
				log.Fatal("failed to collect audit records from pcapng file: ", err)
			}
		}

		// memory profiling
		if c.Bool("memprof") {
			f, errProfile := os.Create("netcap-" + netcap.Version + ".mem.profile")
			if errProfile != nil {
				log.Fatal("failed create memory profile: ", errProfile)
			}

			if err := pprof.WriteHeapProfile(f); err != nil {
				log.Fatal("failed to write heap profile: ", err)
			}

			err := f.Close()
			if err != nil {
				panic("failed to write memory profile: " + err.Error())
			}
		}
	default:
		log.Fatal("nothing to do.")
	}

	// wait until the end of time
	<-make(chan bool)
	return nil
}
