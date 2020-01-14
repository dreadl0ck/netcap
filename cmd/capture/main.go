/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/evilsocket/islazy/tui"
	"github.com/mgutz/ansi"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/utils"
)

func main() {

	// parse commandline flags
	flag.Usage = printUsage
	flag.Parse()

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	// print a markdown overview of all available encoders and fields
	if *flagPrintProtocolOverview {
		encoder.MarkdownOverview()
		return
	}

	// configure CPU profiling
	if *flagCPUProfile {
		defer func() func() {
			if *flagCPUProfile {
				f, err := os.Create("netcap-" + netcap.Version + ".cpu.profile")
				if err != nil {
					log.Fatalf("could not open cpu profile file %q", "netcap.cpu.profile")
				}
				if err := pprof.StartCPUProfile(f); err != nil {
					log.Fatal("failed to start CPU profiling")
				}
				return func() {
					pprof.StopCPUProfile()
					err := f.Close()
					if err != nil {
						panic("failed to write CPU profile: " + err.Error())
					}
				}
			}
			return func() {}
		}()
	}

	// print encoders and exit
	if *flagEncoders {
		encoder.ShowEncoders()
		return
	}

	// live mode?
	var live bool
	if *flagInterface != "" {
		live = true
	}

	// abort if there is no input or no live capture
	if *flagInput == "" && !live {
		printHeader()
		fmt.Println(ansi.Red + "> nothing to do. need a pcap or netcap file with the read flag (-r) or live mode and an interface (-iface)" + ansi.Reset)
		os.Exit(1)
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

	// init collector
	c := collector.New(collector.Config{
		Live:                live,
		Workers:             *flagWorkers,
		PacketBufferSize:    *flagPacketBuffer,
		WriteUnknownPackets: !*flagIngoreUnknown,
		Promisc:             *flagPromiscMode,
		SnapLen:             *flagSnapLen,
		EncoderConfig: encoder.Config{
			Buffer:          *flagBuffer,
			Compression:     *flagCompress,
			CSV:             *flagCSV,
			IncludeEncoders: *flagInclude,
			ExcludeEncoders: *flagExclude,
			Out:             *flagOutDir,
			Source:          source,
			Version:         netcap.Version,
			IncludePayloads: *flagPayload,
			Export:          false,
			AddContext:      *flagContext,
		},
		BaseLayer:     utils.GetBaseLayer(*flagBaseLayer),
		DecodeOptions: utils.GetDecodeOptions(*flagDecodeOptions),
	})

	netcap.PrintLogo()

	fmt.Println("\n> go runtime version:", runtime.Version())
	var lt gopacket.LayerType

	fmt.Println("> gopacket lib:", reflect.TypeOf(lt).PkgPath())

	b, ok := debug.ReadBuildInfo()
	if ok {
		for _, d := range b.Deps {
			if path.Base(d.Path) == "gopacket" {
				fmt.Println("> gopacket version:", d.Version)
			}
		}
	}

	// print configuration as table
	tui.Table(os.Stdout, []string{"Setting", "Value"}, [][]string{
		{"Workers", strconv.Itoa(*flagWorkers)},
		{"MemBuffer", strconv.FormatBool(*flagBuffer)},
		{"Compression", strconv.FormatBool(*flagCompress)},
		{"PacketBuffer", strconv.Itoa(*flagPacketBuffer)},
		{"PacketContext", strconv.FormatBool(*flagContext)},
	})
	fmt.Println() // add a newline

	// collect traffic live from named interface
	if live {
		err := c.CollectLive(*flagInterface, *flagBPF)
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
		if err := c.CollectBPF(*flagInput, *flagBPF); err != nil {
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
		if err := c.CollectPcap(*flagInput); err != nil {
			log.Fatal("failed to collect audit records from pcap file: ", err)
		}
	} else {
		if err := c.CollectPcapNG(*flagInput); err != nil {
			log.Fatal("failed to collect audit records from pcapng file: ", err)
		}
	}

	fmt.Println("done in", time.Since(start))

	// memory profiling
	if *flagMemProfile {
		f, err := os.Create("netcap-" + netcap.Version + ".mem.profile")
		if err != nil {
			log.Fatal("failed create memory profile: ", err)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("failed to write heap profile: ", err)
		}
		err = f.Close()
		if err != nil {
			panic("failed to write memory profile: " + err.Error())
		}
	}
}
