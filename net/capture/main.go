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

package capture

import (
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/mgutz/ansi"
	"github.com/spf13/cobra"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/evilsocket/islazy/tui"
)

func GetCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent for collecting netcap audit records",
		Run: func(cmd *cobra.Command, args []string) {

			// print a markdown overview of all available encoders and fields
			if flagPrintProtocolOverview {
				encoder.MarkdownOverview()
				return
			}

			// configure CPU profiling
			if flagCPUProfile {
				defer func() func() {
					if flagCPUProfile {
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
			if flagEncoders {
				encoder.ShowEncoders()
				return
			}

			// live mode?
			var live bool
			if flagInterface != "" {
				live = true
			}

			// abort if there is no input or no live capture
			if flagInput == "" && !live {
				fmt.Println(ansi.Red + "> nothing to do. need a pcap or netcap file with the read flag (-r) or live mode and an interface (-iface)" + ansi.Reset)
				os.Exit(1)
			}

			// set data source
			var source string
			if flagInput != "" {
				source = flagInput
			} else if flagInterface != "" {
				source = flagInterface
			} else {
				source = "unknown"
			}

			// init collector
			c := collector.New(collector.Config{
				Live:                live,
				Workers:             flagWorkers,
				PacketBufferSize:    flagPacketBuffer,
				WriteUnknownPackets: !flagIngoreUnknown,
				Promisc:             flagPromiscMode,
				SnapLen:             flagSnapLen,
				EncoderConfig: encoder.Config{
					Buffer:          flagBuffer,
					Compression:     flagCompress,
					CSV:             false,
					IncludeEncoders: flagInclude,
					ExcludeEncoders: flagExclude,
					Out:             flagOutDir,
					Source:          source,
					Version:         netcap.Version,
					IncludePayloads: flagPayload,
					Export:          false,
				},
				BaseLayer:     utils.GetBaseLayer(flagBaseLayer),
				DecodeOptions: utils.GetDecodeOptions(flagDecodeOptions),
			})

			netcap.PrintLogo()

			// print configuration as table
			tui.Table(os.Stdout, []string{"Setting", "Value"}, [][]string{
				{"Workers", strconv.Itoa(flagWorkers)},
				{"MemBuffer", strconv.FormatBool(flagBuffer)},
				{"Compression", strconv.FormatBool(flagCompress)},
				{"PacketBuffer", strconv.Itoa(flagPacketBuffer)},
			})
			fmt.Println() // add a newline

			// collect traffic live from named interface
			if live {
				err := c.CollectLive(flagInterface, flagBPF)
				if err != nil {
					log.Fatal("failed to collect live packets: ", err)
				}
				return
			}

			// start timer
			start := time.Now()

			// in case a BPF should be set, the gopacket/pcap version with libpcap bindings needs to be used
			// setting BPF filters is not yet supported by the pcapgo package
			if flagBPF != "" {
				if err := c.CollectBPF(flagInput, flagBPF); err != nil {
					log.Fatal("failed to set BPF: ", err)
				}
				return
			}

			// if not, use native pcapgo version
			isPcap, err := collector.IsPcap(flagInput)
			if err != nil {
				// invalid path
				fmt.Println("failed to open file:", err)
				os.Exit(1)
			}

			// logic is split for both types here
			// because the pcapng reader offers ZeroCopyReadPacketData()
			if isPcap {
				if err := c.CollectPcap(flagInput); err != nil {
					log.Fatal("failed to collect audit records from pcap file: ", err)
				}
			} else {
				if err := c.CollectPcapNG(flagInput); err != nil {
					log.Fatal("failed to collect audit records from pcapng file: ", err)
				}
			}

			fmt.Println("done in", time.Since(start))

			// memory profiling
			if flagMemProfile {
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
		},
	}

	cmd.Flags().BoolVarP(&flagEncoders, "encoders", "e", false, "show all available encoders")
	cmd.Flags().BoolVarP(&flagPromiscMode, "promisc", "p", true, "capture live in promisc mode")
	cmd.Flags().BoolVarP(&flagPayload, "payload", "P", false, "capture payload for supported layers")
	cmd.Flags().BoolVarP(&flagPrintProtocolOverview, "overview", "", false, "print a list of all available encoders and fields")
	cmd.Flags().BoolVarP(&flagCompress, "comp", "", true, "compress output with gzip")
	cmd.Flags().BoolVarP(&flagBuffer, "buf", "", true, "buffer data in memory before writing to disk")
	cmd.Flags().BoolVarP(&flagCPUProfile, "cpuprof", "", false, "create cpu profile")
	cmd.Flags().BoolVarP(&flagMemProfile, "memprof", "", false, "create memory profile")
	cmd.Flags().BoolVarP(&flagIngoreUnknown, "ignore", "", false, "disable writing unknown packets into a pcap file")
	cmd.Flags().BoolVarP(&flagVersion, "version", "", false, "print netcap package version and exit")

	cmd.Flags().StringVarP(&flagInterface, "iface", "i", "en0", "interface")
	cmd.Flags().StringVarP(&flagBPF, "bpf", "B", "", "supply a BPF filter to use for netcap collection")
	cmd.Flags().StringVarP(&flagInclude, "include", "I", "", "include specific encoders")
	cmd.Flags().StringVarP(&flagExclude, "exclude", "E", "", "exclude specific encoders")
	cmd.Flags().StringVarP(&flagBaseLayer, "base", "b", "ethernet", "select base layer")
	cmd.Flags().StringVarP(&flagDecodeOptions, "opts", "", "lazy", "select decoding options")
	cmd.Flags().StringVarP(&flagInput, "read", "r", "", "read specified file, can either be a pcap or netcap audit record file")
	cmd.Flags().StringVarP(&flagOutDir, "out", "o", "", "specify output directory, will be created if it does not exist")

	cmd.Flags().IntVarP(&flagWorkers, "workers", "w", 100, "number of encoder routines")
	cmd.Flags().IntVarP(&flagPacketBuffer, "pbuf", "", 0, "set packet buffer size")
	cmd.Flags().IntVarP(&flagSnapLen, "snaplen", "s", 1024, "configure snaplen for live capture")

	return cmd
}
