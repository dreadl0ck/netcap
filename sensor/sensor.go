/*
 * NETCAP - Network Capture Toolkit
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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/dreadl0ck/cryptoutils"
	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/collector"
	"github.com/dreadl0ck/netcap/encoder"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// maxBufferSize specifies the size of the buffers that
// are used to temporarily hold data from the UDP packets
// that we receive.
const (
	maxBufferSize = 10 * 1024
	timeout       = 1 * time.Minute
)

var (
	flagInterface = flag.String("iface", "en0", "interface")
	flagMaxSize   = flag.Int("max", 10*1024, "max size of packet") // max 65,507 bytes
	flagProto     = flag.String("proto", "TCP", "proto to collect")

	flagBPF      = flag.String("bpf", "", "supply a BPF filter to use for netcap collection")
	flagInclude  = flag.String("include", "", "include specific encoders")
	flagExclude  = flag.String("exclude", "", "exclude specific encoders")
	flagEncoders = flag.Bool("encoders", false, "show all available encoders")

	flagWorkers      = flag.Int("workers", 100, "number of encoder routines")
	flagPacketBuffer = flag.Int("pbuf", 0, "set packet buffer size")
	flagPromiscMode  = flag.Bool("promisc", true, "capture live in promisc mode")
	flagSnapLen      = flag.Int("snaplen", 1024, "configure snaplen for live capture")

	flagServerPubKey = flag.String("pubkey", "", "path to the hex encoded server public key on disk")
	flagAddr         = flag.String("addr", "127.0.0.1:1335", "specify the address and port of the collection server")
)

func main() {

	flag.Parse()

	if *flagServerPubKey == "" {
		fmt.Println("need public key of server")
		os.Exit(1)
	}

	pubKeyContents, err := ioutil.ReadFile(*flagServerPubKey)
	if err != nil {
		panic(err)
	}

	var serverPubKey [cryptoutils.KeySize]byte
	_, err = hex.Decode(serverPubKey[:], pubKeyContents)
	if err != nil {
		panic(err)
	}

	if *flagEncoders {
		encoder.ShowEncoders()
		return
	}

	pub, priv, err := cryptoutils.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	// init collector
	c := collector.New(collector.Config{
		Live:                true,
		Workers:             *flagWorkers,
		PacketBufferSize:    *flagPacketBuffer,
		WriteUnknownPackets: false,
		Promisc:             *flagPromiscMode,
		SnapLen:             *flagSnapLen,
		EncoderConfig: encoder.Config{
			// needs to be disabled
			Buffer:          false,
			Compression:     false,
			CSV:             false,
			IncludeEncoders: *flagInclude,
			ExcludeEncoders: *flagExclude,
			Out:             "",
			Version:         netcap.Version,
			Source:          *flagInterface,

			// set channel writer
			WriteChan: true,
		},
	})

	chans, handle := c.InitBatching(*flagMaxSize, *flagBPF, *flagInterface)
	defer handle.Close()

	var userName = os.Getenv("USER")
	fmt.Println("\n["+userName+"] got", len(chans), "channels")

	for _, bi := range chans {

		// create a copy of loop variable
		info := collector.BatchInfo{
			Type: bi.Type,
			Chan: bi.Chan,
		}

		// handle channel goroutine
		go func() {

			var (
				leftOverBuf []byte
			)

			// send data loop
			for {

				var (
					b    = &types.Batch{}
					size []byte
				)

				b.ClientID = userName
				b.MessageType = info.Type

				if len(leftOverBuf) > 0 {
					b.Data = append(b.Data, leftOverBuf...)
					b.Size = int32(len(leftOverBuf))
					leftOverBuf = make([]byte, 0)
				}

				// read chan loop
				for {

					select {
					case data := <-info.Chan:

						// message complete
						if len(size) != 0 {

							fmt.Println("got", len(data), "bytes of type", info.Type, "expected", size)

							newSize := int32(len(size)+len(data)) + b.Size
							if newSize > int32(*flagMaxSize) {
								// buffer and break from loop
								leftOverBuf = append(size, data...)
								goto send
							}
							b.Data = append(b.Data, append(size, data...)...)
							b.Size = newSize

							size = []byte{}
							continue
						}

						// received a size as varint
						fmt.Println("got size", data, "for type", info.Type)
						size = data
					}
				}

			send:

				fmt.Println("\nBatch done!", b.Size, len(b.Data), b.ClientID, b.MessageType)

				d, err := proto.Marshal(b)
				if err != nil {
					panic(err)
				}

				// compress
				var buf bytes.Buffer
				gw := gzip.NewWriter(&buf)
				_, err = gw.Write(d)
				if err != nil {
					panic(err)
				}
				err = gw.Flush()
				if err != nil {
					panic(err)
				}
				err = gw.Close()
				if err != nil {
					panic(err)
				}

				encData, err := cryptoutils.AsymmetricEncrypt(buf.Bytes(), &serverPubKey, priv)
				if err != nil {
					panic(err)
				}

				var encB bytes.Buffer
				encB.Write(pub[:])
				encB.Write(encData)

				// send to server
				err = client(context.Background(), *flagAddr, &encB)
				if err != nil {
					panic(err)
				}
			}
		}()
	}

	wait := make(chan bool)
	<-wait

	// for {
	// 	batch, err := c.CollectBatch(*flagProto, *flagMaxSize, *flagBPF, *flagInterface)
	// 	if err == io.EOF {
	// 		fmt.Println("EOF")
	// 		break
	// 	} else if err != nil {
	// 		panic(err)
	// 	}

	// 	fmt.Println("\nBatch done!", batch.Size, len(batch.Data), batch.ClientID, batch.MessageType)

	// 	d, err := proto.Marshal(batch)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	// compress
	// 	var buf bytes.Buffer
	// 	gw := gzip.NewWriter(&buf)
	// 	_, err = gw.Write(d)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	err = gw.Flush()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	err = gw.Close()
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	// send to server
	// 	err = client(context.Background(), "127.0.0.1:1335", &buf)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
}
