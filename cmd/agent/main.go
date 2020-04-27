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
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dreadl0ck/netcap/resolvers"
	"io/ioutil"
	"os"

	"compress/gzip"

	"github.com/dreadl0ck/cryptoutils"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
)

func Run() {

	// parse commandline flags
	fs.Usage = printUsage
	fs.Parse(os.Args[2:])

	if *flagGenerateConfig {
		netcap.GenerateConfig(fs, "agent")
		return
	}

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	netcap.PrintBuildInfo()

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

	if *flagEncoders {
		encoder.ShowEncoders()
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
		EncoderConfig: encoder.Config{
			// needs to be disabled for batch mode
			Buffer:          false,
			Compression:     false,
			CSV:             false,
			IncludeEncoders: *flagInclude,
			ExcludeEncoders: *flagExclude,
			Out:             "",
			Source:          *flagInterface,

			// set channel writer
			WriteChan:            true,
			IncludePayloads:      *flagPayload,
			AddContext:           *flagContext,
			MemBufferSize:        *flagMemBufferSize,
			FlushEvery:           *flagFlushevery,
			NoDefrag:             *flagNodefrag,
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
	chans, handle, err := c.InitBatching(*flagMaxSize, *flagBPF, *flagInterface)
	if err != nil {
		panic(err)
	}

	// close handle on exit
	defer handle.Close()

	// get client id
	// currently the user name is used for this
	// TODO: generate a unique numerical identifier instead
	var userName = os.Getenv("USER")
	fmt.Println("\n["+userName+"] got", len(chans), "channels")

	// iterate over encoder channels
	for _, bi := range chans {

		// create a copy of loop variable
		info := collector.BatchInfo{
			Type: bi.Type,
			Chan: bi.Chan,
		}

		// handle channel goroutine
		go func() {

			var leftOverBuf []byte

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
					case data := <-info.Chan:

						// message complete
						if len(size) != 0 {

							fmt.Println("got", len(data), "bytes of type", info.Type, "expected", size)

							// calculate new size
							newSize := int32(len(size)+len(data)) + b.TotalSize

							// if the new size would exceed the maximum size
							if newSize > int32(*flagMaxSize) {
								// buffer and break from loop
								leftOverBuf = append(size, data...)
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
				d, err := proto.Marshal(b)
				if err != nil {
					panic(err)
				}

				// compress data
				var buf bytes.Buffer
				gw := gzip.NewWriter(&buf)
				_, err = gw.Write(d)
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
				encData, err := cryptoutils.AsymmetricEncrypt(buf.Bytes(), &serverPubKey, priv)
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
