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

package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	gzip "github.com/klauspost/pgzip"

	"github.com/dreadl0ck/cryptoutils"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
	"github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
)

func GetCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent for collecting netcap audit records",
		Run: func(cmd *cobra.Command, args []string) {

			// no server public key specified - no party
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

			if flagEncoders {
				encoder.ShowEncoders()
				return
			}

			// create keypair
			pub, priv, err := cryptoutils.GenerateKeypair()
			if err != nil {
				panic(err)
			}

			// init collector
			c := collector.New(collector.Config{
				Live:                true,
				Workers:             flagWorkers,
				PacketBufferSize:    flagPacketBuffer,
				WriteUnknownPackets: false,
				Promisc:             flagPromiscMode,
				SnapLen:             flagSnapLen,
				EncoderConfig: encoder.Config{
					// needs to be disabled for batch mode
					Buffer:          false,
					Compression:     false,
					CSV:             false,
					IncludeEncoders: flagInclude,
					ExcludeEncoders: flagExclude,
					Out:             "",
					Version:         netcap.Version,
					Source:          flagInterface,

					// set channel writer
					WriteChan:       true,
					IncludePayloads: flagPayload,
				},
				BaseLayer:     utils.GetBaseLayer(flagBaseLayer),
				DecodeOptions: utils.GetDecodeOptions(flagDecodeOptions),
			})

			// initialize batching
			chans, handle, err := c.InitBatching(flagMaxSize, flagBPF, flagInterface)
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
									if newSize > int32(flagMaxSize) {
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
						err = sendUDP(context.Background(), flagAddr, &encB)
						if err != nil {
							panic(err)
						}
					}
				}()
			}

			// wait until the end of time
			wait := make(chan bool)
			<-wait
		},
	}

	// flagEncoders      = flag.Bool("encoders", false, "show all available encoders")
	// flagPromiscMode   = flag.Bool("promisc", true, "capture live in promisc mode")
	// flagPayload       = flag.Bool("payload", false, "capture payload for supported layers")
	cmd.Flags().BoolVarP(&flagEncoders, "encoders", "e", false, "show all available encoders")
	cmd.Flags().BoolVarP(&flagPromiscMode, "promisc", "p", true, "capture live in promisc mode")
	cmd.Flags().BoolVarP(&flagPayload, "payload", "P", false, "capture payload for supported layers")

	// flagInterface     = flag.String("iface", "en0", "interface")
	// flagBPF           = flag.String("bpf", "", "supply a BPF filter to use for netcap collection")
	// flagInclude       = flag.String("include", "", "include specific encoders")
	// flagExclude       = flag.String("exclude", "", "exclude specific encoders")
	// flagServerPubKey  = flag.String("pubkey", "", "path to the hex encoded server public key on disk")
	// flagAddr          = flag.String("addr", "127.0.0.1:1335", "specify the address and port of the collection server")
	// flagBaseLayer     = flag.String("base", "ethernet", "select base layer")
	// flagDecodeOptions = flag.String("opts", "lazy", "select decoding options")
	cmd.Flags().StringVarP(&flagInterface, "iface", "i", "en0", "interface")
	cmd.Flags().StringVarP(&flagBPF, "bpf", "B", "", "supply a BPF filter to use for netcap collection")
	cmd.Flags().StringVarP(&flagInclude, "include", "I", "", "include specific encoders")
	cmd.Flags().StringVarP(&flagExclude, "exclude", "E", "", "exclude specific encoders")
	cmd.Flags().StringVarP(&flagServerPubKey, "pubkey", "", "", "path to the hex encoded server public key on disk")
	cmd.Flags().StringVarP(&flagAddr, "addr", "a", "127.0.0.1:1335", "specify the address and port of the collection server")
	cmd.Flags().StringVarP(&flagBaseLayer, "base", "b", "ethernet", "select base layer")
	cmd.Flags().StringVarP(&flagDecodeOptions, "opts", "o", "lazy", "select decoding options")

	// flagMaxSize       = flag.Int("max", 10*1024, "max size of packet") // max 65,507 bytes
	// flagWorkers       = flag.Int("workers", 100, "number of encoder routines")
	// flagPacketBuffer  = flag.Int("pbuf", 0, "set packet buffer size")
	// flagSnapLen       = flag.Int("snaplen", 1024, "configure snaplen for live capture")
	cmd.Flags().IntVarP(&flagMaxSize, "max", "m", 10*1024, "max size of packet") // max 65,507 bytes
	cmd.Flags().IntVarP(&flagWorkers, "workers", "w", 100, "number of encoder routines")
	cmd.Flags().IntVarP(&flagPacketBuffer, "pbuf", "", 0, "set packet buffer size")
	cmd.Flags().IntVarP(&flagSnapLen, "snaplen", "s", 1514, "configure snaplen for live capture")

	return cmd
}
