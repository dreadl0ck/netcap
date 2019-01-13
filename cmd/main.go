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
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"
)

func main() {

	flag.Parse()

	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	if *flagPrintProtocolOverview {
		encoder.Overview()
		return
	}

	if *flagToUTC != "" {
		fmt.Println(utils.TimeToUTC(*flagToUTC))
		os.Exit(1)
	}

	if *flagCPUProfile {
		defer func() func() {
			if *flagCPUProfile {
				f, err := os.Create("netcap-" + netcap.Version + ".cpu.profile")
				if err != nil {
					log.Fatalf("could not open cpu profile file %q", "netcap.cpu.profile")
				}
				pprof.StartCPUProfile(f)
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

	if *flagInput == "" && !live {
		fmt.Println("nothing to do. need a pcap or netcap file with the read flag (-r) or live mode enabled.")
		os.Exit(1)
	}

	// check if fields count matches for all generated rows
	if *flagCheckFields {
		CheckFields()
		return
	}

	if *flagHeader {
		// open input file for reading
		r, err := netcap.Open(*flagInput)
		if err != nil {
			panic(err)
		}

		// get header
		// this will panic if the header is corrupted
		h := r.ReadHeader()

		// print result as table
		tui.Table(os.Stdout, []string{"Field", "Value"}, [][]string{
			{"Created", utils.TimeToUTC(h.Created)},
			{"Source", h.InputSource},
			{"Version", h.Version},
			{"Type", h.Type.String()},
			{"ContainsPayloads", strconv.FormatBool(h.ContainsPayloads)},
		})
		os.Exit(0) // bye bye
	}

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
		},
		BaseLayer:     utils.GetBaseLayer(*flagBaseLayer),
		DecodeOptions: utils.GetDecodeOptions(*flagDecodeOptions),
	})

	// read ncap file and print to stdout
	if filepath.Ext(*flagInput) == ".ncap" || filepath.Ext(*flagInput) == ".gz" {
		netcap.Dump(*flagInput, *flagSeparator, *flagTSV, *flagPrintStructured, *flagTable, *flagSelect, *flagUTC, *flagFields)
		return
	}

	printLogo()

	// print configuration as table
	tui.Table(os.Stdout, []string{"Setting", "Value"}, [][]string{
		{"Workers", strconv.Itoa(*flagWorkers)},
		{"MemBuffer", strconv.FormatBool(*flagBuffer)},
		{"Compression", strconv.FormatBool(*flagCompress)},
		{"PacketBuffer", strconv.Itoa(*flagPacketBuffer)},
	})
	fmt.Println() // add a newline

	// collect traffic live from named interface
	if live {
		err := c.CollectLive(*flagInterface, *flagBPF)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	// start timer
	start := time.Now()

	// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
	// setting BPF filters is not yet supported by the pcapgo package
	if *flagBPF != "" {
		if err := c.CollectBPF(*flagInput, *flagBPF); err != nil {
			log.Fatal(err)
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
		c.CollectPcap(*flagInput)
	} else {
		c.CollectPcapNG(*flagInput)
	}

	fmt.Println("done in", time.Since(start))

	if *flagMemProfile {
		f, err := os.Create("netcap-" + netcap.Version + ".mem.profile")
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		err = f.Close()
		if err != nil {
			panic("failed to write memory profile: " + err.Error())
		}
	}
}
