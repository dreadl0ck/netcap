/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/denisbrodbeck/machineid"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/internal/cryptoutils"
	"github.com/urfave/cli/v3"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/io"
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
		Name:  "agent",
		Usage: "agent for distributed capture",
		Flags: GetFlags(),
		Action: func(ctx context.Context, c *cli.Command) error {
			return RunWithContext(ctx, c)
		},
	}

	if err := cmd.Run(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

// RunWithContext runs the agent command with a CLI context.
func RunWithContext(ctx context.Context, c *cli.Command) error {
	if c.Bool("gen-config") {
		// TODO: Update GenerateConfig to work with urfave/cli
		fmt.Println("gen-config not yet implemented with urfave/cli")
		return nil
	}

	io.PrintBuildInfo()

	// no server public key specified - no party
	flagServerPubKey := c.String("pubkey")
	if flagServerPubKey == "" {
		fmt.Println("need public key of server")
		os.Exit(1)
	}

	// read server public key contents from file
	pubKeyContents, err := ioutil.ReadFile(flagServerPubKey)
	if err != nil {
		panic(err)
	}

	// decode server public key
	var serverPubKey [cryptoutils.KeySize]byte

	_, err = hex.Decode(serverPubKey[:], pubKeyContents)
	if err != nil {
		panic(err)
	}

	if c.Bool("decoders") {
		packet.ShowDecoders(true)
		return nil
	}

	if c.Bool("interfaces") {
		utils.ListAllNetworkInterfaces()
		return nil
	}

	// create keypair
	pub, priv, err := cryptoutils.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	// init collector
	coll := collector.New(collector.Config{
		Workers:             c.Int("workers"),
		PacketBufferSize:    c.Int("pbuf"),
		WriteUnknownPackets: false,
		Promisc:             c.Bool("promisc"),
		SnapLen:             c.Int("snaplen"),
		LogErrors:           c.Bool("log-errors"),
		DecoderConfig: &config.Config{
			Buffer:               false,
			Compression:          false,
			CSV:                  false,
			Chan:                 true,
			ChanSize:             c.Int("chan-size"),
			IncludeDecoders:      c.String("include"),
			ExcludeDecoders:      c.String("exclude"),
			Out:                  "",
			Source:               c.String("iface"),
			IncludePayloads:      c.Bool("payload"),
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
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:    c.Bool("reverse-dns"),
			LocalDNS:      c.Bool("local-dns"),
			MACDB:         c.Bool("macDB"),
			ServiceDB:     c.Bool("serviceDB"),
			GeolocationDB: c.Bool("geoDB"),
		},
		DPI:           c.Bool("dpi"),
		DPIModules:    c.String("dpi-modules"),
		BaseLayer:     utils.GetBaseLayer(c.String("base")),
		DecodeOptions: utils.GetDecodeOptions(c.String("opts")),
	})

	// initialize batching
	chans, handle, err := coll.InitBatching(c.String("bpf"), c.String("iface"))
	if err != nil {
		panic(err)
	}

	// close handle on exit
	defer handle.Close()

	// get client id: $USER-$MACHINEID
	userName := os.Getenv("USER")
	id, err := machineid.ID()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n["+userName+"-"+id+"] got", len(chans), "channels")

	// iterate over decoder channels
	for _, bi := range chans { // create a copy of loop variable
		info := collector.BatchInfo{
			Type: bi.Type,
			Chan: bi.Chan,
		}

		// handle channel goroutine
		go func() {
			var (
				leftOverBuf []byte
				data        []byte
			)

			// send data loop
			for {
				var (
					b    = &types.Batch{}
					size []byte
				)

				// set clientID and messageType
				b.ClientID = userName
				b.MessageType = info.Type

				// if there is buffered data left over
				if len(leftOverBuf) > 0 {
					// add to current batch
					b.Data = append(b.Data, leftOverBuf...)
					b.TotalSize = int32(len(leftOverBuf))

					// reset leftover buffer
					leftOverBuf = make([]byte, 0)
				}

				// read chan loop
				for {
					select {
					case data = <-info.Chan:
						// message complete
						if len(size) != 0 {
							fmt.Println("got", len(data), "bytes of type", info.Type, "expected", size)

							// calculate new size
							newSize := int32(len(size)+len(data)) + b.TotalSize

							// if the new size would exceed the maximum size
							if newSize > int32(c.Int("max")) {
								// buffer and break from loop
								leftOverBuf = append(size, data...) //nolint:gocritic // append to different slice is intended here!

								goto send
							}

							// collect data
							b.Data = append(b.Data, append(size, data...)...)

							// update batch size
							b.TotalSize = newSize

							// reset size slice
							size = []byte{}

							continue
						}

						// received a size as varint
						fmt.Println("got size", data, "for type", info.Type)

						// set the size value
						size = data
					}
				}

			send: // send batch to collection server

				fmt.Println("\nBatch done!", b.TotalSize, len(b.Data), b.ClientID, b.MessageType)

				// marshal batch
				data, err = proto.Marshal(b)
				if err != nil {
					panic(err)
				}

				// compress data
				var (
					buf bytes.Buffer
					gw  = gzip.NewWriter(&buf)
				)

				_, err = gw.Write(data)
				if err != nil {
					panic(err)
				}

				// flush compressed writer
				err = gw.Flush()
				if err != nil {
					panic(err)
				}

				// close compressed writer
				err = gw.Close()
				if err != nil {
					panic(err)
				}

				// encrypt payload
				var encData []byte

				encData, err = cryptoutils.AsymmetricEncrypt(buf.Bytes(), &serverPubKey, priv)
				if err != nil {
					panic(err)
				}

				// create a buffer for the encrypted bytes
				var encB bytes.Buffer

				// write public key
				encB.Write(pub[:])
				// write encrypted data
				encB.Write(encData)

				// send to server
				err = sendUDP(context.Background(), c.String("addr"), &encB)
				if err != nil {
					panic(err)
				}
			}
		}()
	}

	// wait until the end of time
	wait := make(chan bool)
	<-wait

	return nil
}
