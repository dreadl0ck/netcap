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
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/cryptoutils"

	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var (
	flagGenKeypair = flag.Bool("gen-keypair", false, "generate keypair")
	flagPrivKey    = flag.String("privkey", "", "path to the hex encoded server private key")
	flagAddr       = flag.String("addr", "127.0.0.1:1335", "specify an adress and port to listen for incoming traffic")

	// not configurable at the moment
	// flagCompress   = flag.Bool("comp", true, "compress data when writing to disk")
	// flagBuffer     = flag.Bool("buf", true, "buffer data before writing to disk")
)

func main() {

	flag.Parse()

	if *flagGenKeypair {
		pub, priv, err := cryptoutils.GenerateKeypair()
		if err != nil {
			panic(err)
		}

		pubFile, err := os.Create("pub.key")
		if err != nil {
			panic(err)
		}
		pubFile.WriteString(hex.EncodeToString(pub[:]))

		err = pubFile.Close()
		if err != nil {
			panic(err)
		}

		privFile, err := os.Create("priv.key")
		if err != nil {
			panic(err)
		}

		privFile.WriteString(hex.EncodeToString(priv[:]))

		err = privFile.Close()
		if err != nil {
			panic(err)
		}

		fmt.Println("wrote keys")
		return
	}

	ctx := context.Background()
	log.Fatal(server(ctx, *flagAddr))
}

// maxBufferSize specifies the size of the buffers that
// are used to temporarily hold data from the UDP packets
// that we receive.
const (
	maxBufferSize = 10 * 1024
	timeout       = 1 * time.Minute
)

// AuditRecordHandle wraps a file handle of a netcap audit record file
// contains the original file handle and writers to compress and buffer the data
type AuditRecordHandle struct {
	gWriter *gzip.Writer
	bWriter *bufio.Writer
	f       *os.File
}

var files = make(map[string]*AuditRecordHandle)

// server wraps all the UDP echo server functionality.
func server(ctx context.Context, address string) (err error) {

	// ListenPacket provides us a wrapper around ListenUDP so that
	// we don't need to call `net.ResolveUDPAddr` and then subsequentially
	// perform a `ListenUDP` with the UDP address.
	//
	// The returned value (PacketConn) is pretty much the same as the one
	// from ListenUDP (UDPConn) - the only difference is that `Packet*`
	// methods and interfaces are more broad, also covering `ip`.
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return
	}

	// `Close`ing the packet "connection" means cleaning the data structures
	// allocated for holding information about the listening socket.
	defer pc.Close()

	var (
		doneChan = make(chan error, 1)
		buffer   = make([]byte, maxBufferSize)
	)

	// run cleanup on signals
	handleSignals()

	// read private key
	privKeyContents, err := ioutil.ReadFile(*flagPrivKey)
	if err != nil {
		panic(err)
	}

	var serverPrivKey [cryptoutils.KeySize]byte
	_, err = hex.Decode(serverPrivKey[:], privKeyContents)
	if err != nil {
		panic(err)
	}

	// Given that waiting for packets to arrive is blocking by nature and we want
	// to be able of canceling such action if desired, we do that in a separate
	// go routine.
	go func() {
		for {
			// By reading from the connection into the buffer, we block until there's
			// new content in the socket that we're listening for new packets.
			//
			// Whenever new packets arrive, `buffer` gets filled and we can continue
			// the execution.
			//
			// note.: `buffer` is not being reset between runs.
			//	  It's expected that only `n` reads are read from it whenever
			//	  inspecting its contents.
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				doneChan <- err
				return
			}

			fmt.Printf("packet-received: bytes=%d from=%s\n", n, addr.String())
			var copyBuf = make([]byte, n)
			copy(copyBuf, buffer[:n])
			buf := bytes.NewBuffer(copyBuf)

			// spawn a new goroutine to handle packet
			go func() {

				// trim off the public key of the peer
				var pubKeyClient = [32]byte{}
				for i, b := range buf.Bytes() {
					if i == 32 {
						break
					}
					pubKeyClient[i] = b
				}

				// decrypt
				decrypted, ok := cryptoutils.AsymmetricDecrypt(buf.Bytes()[32:], &pubKeyClient, &serverPrivKey)
				if !ok {
					panic("decryption failed")
				}

				var decryptedBuf = bytes.NewBuffer(decrypted)

				// decompress
				gr, err := gzip.NewReader(decryptedBuf)
				if err != nil {
					fmt.Println(hex.Dump(decryptedBuf.Bytes()))
					fmt.Println("gzip error", err)
					return
				}
				c, err := ioutil.ReadAll(gr)
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					fmt.Println("failed to decompress batch", err)
					return
				} else if err != nil {
					fmt.Println(hex.Dump(buf.Bytes()))
					fmt.Println("gzip error", err)
					return
				}
				err = gr.Close()
				if err != nil {
					panic(err)
				}

				b := new(types.Batch)
				err = proto.Unmarshal(c, b)
				if err == io.EOF || err == io.ErrUnexpectedEOF {
					fmt.Println("failed to unmarshal batch", err)
					return
				} else if err != nil {
					panic(err)
				}

				fmt.Println("decoded batch", b.MessageType, "from client", b.ClientID)

				protocol := strings.TrimPrefix(b.MessageType.String(), "NC_")

				path := filepath.Join(b.ClientID, protocol+".ncap.gz")
				if a, ok := files[path]; ok {
					_, err := a.gWriter.Write(b.Data)
					if err != nil {
						panic(err)
					}
				} else {
					files[path] = NewAuditRecordHandle(b, path)
				}
			}()

			// print batch data as CSV
			// dReader := delimited.NewReader(bytes.NewBuffer(b.Data))
			// var packet proto.Message = new(types.TCP)

			// for {
			// 	err := dReader.NextProto(packet)
			// 	if err == io.EOF || err == io.ErrUnexpectedEOF {
			// 		fmt.Println("EOF")
			// 		break
			// 	} else if err != nil {
			// 		panic(err)
			// 	}

			// 	if p, ok := packet.(types.CSV); ok {
			// 		fmt.Println(strings.Join(p.CSVRecord(), ","))
			// 	}
			// }

			// // Setting a deadline for the `write` operation allows us to not block
			// // for longer than a specific timeout.
			// //
			// // In the case of a write operation, that'd mean waiting for the send
			// // queue to be freed enough so that we are able to proceed.
			// deadline := time.Now().Add(timeout)
			// err = pc.SetWriteDeadline(deadline)
			// if err != nil {
			// 	doneChan <- err
			// 	return
			// }

			// // Write the packet's contents back to the client.
			// n, err = pc.WriteTo(buffer[:n], addr)
			// if err != nil {
			// 	doneChan <- err
			// 	return
			// }

			// fmt.Printf("packet-written: bytes=%d to=%s\n", n, addr.String())
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("cancelled")
		err = ctx.Err()
	case err = <-doneChan:
		cleanup()
	}

	return
}
