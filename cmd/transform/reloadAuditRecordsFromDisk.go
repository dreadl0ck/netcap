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

package transform

import (
	"log"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/io"
)

func reloadAuditRecordsFromDisk() {
	// setup logger for io pkg
	ioLog := zap.New(zapcore.NewNopCore())
	defer func() {
		err := ioLog.Sync()
		if err != nil {
			log.Println(err)
		}
	}()

	io.SetLogger(ioLog)

	var (
		lt        = maltego.ParseLocalArguments(os.Args[3:])
		inputFile = strings.TrimPrefix(lt.Values["path"], "file://")
	)

	// check if input PCAP path is set
	if inputFile == "" {
		maltego.Die("input file path property not set", "")
	}

	log.Println("inputFile:", inputFile)

	// create the output directory in the same place as the input file
	// the directory for this will be named like the input file with an added .net extension
	outDir := inputFile + ".net"

	log.Println("path:", outDir, "iface", lt.Value)
	writeLiveAuditRecords(outDir)
}
