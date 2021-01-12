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
	"github.com/dreadl0ck/cryptoutils"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/io"
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
		io.GenerateConfig(fs, "agent")

		return
	}

	io.PrintBuildInfo()

	// no server public key specified - no party
	if *flagServerPubKey == "" {
		fmt.Println("need public key of server")
		os.Exit(1)
	}

	// read server public key contents from file
	pubKeyContents, err := ioutil.ReadFile(*flagServerPubKey)
	if err != nil {
		panic(err)
	}

	// decode server public key
	var serverPubKey [cryptoutils.KeySize]byte

	_, err = hex.Decode(serverPubKey[:], pubKeyContents)
	if err != nil {
		panic(err)
	}

	if *flagDecoders {
		packet.ShowDecoders(true)

		return
	}

	if *flagListInterfaces {
		utils.ListAllNetworkInterfaces()

		return
	}

	// create keypair
	pub, priv, err := cryptoutils.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	// init collector
	c := collector.New(collector.Config{
		Workers:             *flagWorkers,
		PacketBufferSize:    *flagPacketBuffer,
		WriteUnknownPackets: false,
		Promisc:             *flagPromiscMode,
		SnapLen:             *flagSnapLen,
		LogErrors:           *flagLogErrors,
		DecoderConfig: &config.Config{
			Buffer:               false,
			Compression:          false,
			CSV:                  false,
			Chan:                 true,
			ChanSize:             *flagChanSize,
			IncludeDecoders:      *flagInclude,
			ExcludeDecoders:      *flagExclude,
			Out:                  "",
			Source:               *flagInterface,
			IncludePayloads:      *flagPayload,
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
		},
		ResolverConfig: resolvers.Config{
			ReverseDNS:    *flagReverseDNS,
			LocalDNS:      *flagLocalDNS,
			MACDB:         *flagMACDB,
			Ja3DB:         *flagJa3DB,
			ServiceDB:     *flagServiceDB,
			GeolocationDB: *flagGeolocationDB,
		},
		DPI:           *flagDPI,
		BaseLayer:     utils.GetBaseLayer(*flagBaseLayer),
		DecodeOptions: utils.GetDecodeOptions(*flagDecodeOptions),
	})

	// initialize batching
	chans, handle, err := c.InitBatching(*flagBPF, *flagInterface)
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
							if newSize > int32(*flagMaxSize) {
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
				err = sendUDP(context.Background(), *flagAddr, &encB)
				if err != nil {
					panic(err)
				}
			}
		}()
	}

	// wait until the end of time
	wait := make(chan bool)
	<-wait
}
