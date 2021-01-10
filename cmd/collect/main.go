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

package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/cryptoutils"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// maxBufferSize specifies the size of the buffers that
// are used to temporarily hold data from the UDP packets
// that we receive.
const (
	maxBufferSize = 10 * 1024
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
		netio.GenerateConfig(fs, "collect")

		return
	}

	netio.PrintBuildInfo()

	if *flagGenKeypair {

		// generate a new keypair
		pub, priv, errGenKey := cryptoutils.GenerateKeypair()
		if errGenKey != nil {
			panic(errGenKey)
		}

		// write public key to file on disk
		pubFile, errCreateKey := os.Create("pub.key")
		if errCreateKey != nil {
			panic(errCreateKey)
		}

		if _, errWrite := pubFile.WriteString(hex.EncodeToString(pub[:])); errWrite != nil {
			panic(errWrite)
		}

		// close file handle
		err = pubFile.Close()
		if err != nil {
			panic(err)
		}

		// write private key to file on disk
		privFile, errCreatePriv := os.Create("priv.key")
		if errCreatePriv != nil {
			panic(errCreatePriv)
		}

		if _, errWrite := privFile.WriteString(hex.EncodeToString(priv[:])); errWrite != nil {
			panic(errWrite)
		}

		// close file handle
		err = privFile.Close()
		if err != nil {
			panic(err)
		}

		fmt.Println("wrote keys")

		return
	}

	if *flagPrivKey == "" {
		log.Fatal("no path to private key specified")
	}

	// serve
	ctx := context.Background()
	log.Fatal(udpServer(ctx, *flagAddr))
}

// udpServer implements a simple UDP server.
func udpServer(ctx context.Context, address string) (err error) {
	// ListenPacket provides a wrapper around ListenUDP
	// eliminating the need to call net.ResolveUDPAddr
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
	defer func() {
		errClose := pc.Close()
		if errClose != nil && !errors.Is(errClose, io.EOF) {
			fmt.Println("failed to close:", errClose)
		}
	}()

	var (
		doneChan        = make(chan error, 1)
		buffer          = make([]byte, maxBufferSize)
		privKeyContents []byte
	)

	// run cleanup on signals
	handleSignals()

	// read private key file contents
	privKeyContents, err = ioutil.ReadFile(*flagPrivKey)
	if err != nil {
		log.Fatal("failed to read private key file: ", err)
	}

	// hex decode private key
	var serverPrivKey [cryptoutils.KeySize]byte

	_, err = hex.Decode(serverPrivKey[:], privKeyContents)
	if err != nil {
		log.Fatal("failed to decode private key: ", err)
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
			// IMPORTANT: do not use the err variable in this closure! Don't shadow it, don't capture it!
			n, addr, errRead := pc.ReadFrom(buffer)
			if errRead != nil {
				doneChan <- errRead

				return
			}

			fmt.Printf("packet-received: bytes=%d from=%s\n", n, addr.String())

			// create a copy of the data to allow reusing the buffer for the next incoming packet
			copyBuf := make([]byte, n)
			copy(copyBuf, buffer[:n])
			buf := bytes.NewBuffer(copyBuf)

			// spawn a new goroutine to handle packet data
			go func() {
				// trim off the public key of the peer
				pubKeyClient := [32]byte{}

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

				decryptedBuf := bytes.NewBuffer(decrypted)

				// create a new gzipped reader
				// IMPORTANT: do not shadow or use the err variable from outside the closure!
				gr, errProcess := gzip.NewReader(decryptedBuf)
				if errProcess != nil {
					fmt.Println(hex.Dump(decryptedBuf.Bytes()))
					fmt.Println("gzip error", errProcess)

					return
				}

				// read data
				var c []byte
				c, errProcess = ioutil.ReadAll(gr)

				if errors.Is(errProcess, io.EOF) || errors.Is(errProcess, io.ErrUnexpectedEOF) {
					fmt.Println("failed to decompress batch", errProcess)

					return
				} else if errProcess != nil {
					fmt.Println(hex.Dump(buf.Bytes()))
					fmt.Println("gzip error", errProcess)

					return
				}

				// close reader
				errProcess = gr.Close()
				if errProcess != nil {
					panic(errProcess)
				}

				// init new batch
				b := new(types.Batch)

				// unmarshal batch data
				errProcess = proto.Unmarshal(c, b)
				if errors.Is(errProcess, io.EOF) || errors.Is(errProcess, io.ErrUnexpectedEOF) {
					fmt.Println("failed to unmarshal batch", errProcess)

					return
				} else if errProcess != nil {
					panic(errProcess)
				}

				fmt.Println("decoded batch", b.MessageType, "from client", b.ClientID)

				var (
					protocol = strings.TrimPrefix(b.MessageType.String(), defaults.NetcapTypePrefix)
					path     = filepath.Join(b.ClientID, protocol+defaults.FileExtensionCompressed)
				)

				if a, exists := files[path]; exists {
					_, errProcess = a.gWriter.Write(b.Data)
					if errProcess != nil {
						panic(errProcess)
					}
				} else {
					files[path] = newAuditRecordHandle(b, path)
				}
			}()
		}
	}()

	select {
	case <-ctx.Done():
		fmt.Println("canceled")

		err = ctx.Err()
	case err = <-doneChan:
		if err != nil {
			log.Println("encountered an error while collecting audit records: ", err)
		}

		cleanup()
	}

	return
}
