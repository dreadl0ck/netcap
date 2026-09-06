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
	// Alerts are raised by other decoders, so this is reached even when the
	// Alert decoder itself was not selected and has no writer.
	if Decoder.Writer == nil {
		return
	}

	if decoderconfig.Instance.ExportMetrics {
		f.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(f)
	if err != nil {
		log.Println("failed to write Alert audit record:", err)
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
