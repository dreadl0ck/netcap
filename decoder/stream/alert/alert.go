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

package alert

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_Alert,
	Name:        "Alert",
	Description: "An alert based on observations from network traffic",
}

// WriteAlert writeDeviceProfile writes the profile.
func WriteAlert(f *types.Alert) {
	if decoderconfig.Instance.ExportMetrics {
		f.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(f)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}

const networkTypeUnixgram = "unixgram"

// SocketConn contains a pointer to the used socket at runtime.
var SocketConn *net.UnixConn

var errClosed = errors.New("use of closed network connection")

// InitSocket initializes the socket for incoming alerts.
func InitSocket() {

	name := "Alert"
	path := filepath.Join("/tmp/" + name + ".sock")
	if err := os.RemoveAll(path); err != nil {
		log.Fatal(err)
	}

	// Create unix socket
	raddr, err := net.ResolveUnixAddr(networkTypeUnixgram, path)
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.ListenUnixgram(networkTypeUnixgram, raddr)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	SocketConn = l

	fmt.Println("listening for incoming alerts on UNIX socket at", path)

	go func() {
		for {
			// TODO: reuse buffer?
			var buf = make([]byte, 1024)
			n, err := l.Read(buf)
			if err != nil {
				if err != errClosed {
					return
				}
				log.Println("failed to read from UNIX socket", err)
				return
			}
			fmt.Println("read from alert UNIX socket", string(buf[:n]))
		}
	}()
}
