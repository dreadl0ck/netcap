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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/decoder/packet"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/utils"
)

func toLiveAuditRecords() {
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
		lt   = maltego.ParseLocalArguments(os.Args[3:])
		path = getPathLiveCaptureOutDir(lt.Value)
	)

	log.Println("path:", path, "iface", lt.Value)
	writeLiveAuditRecords(path)
}

func writeLiveAuditRecords(outDir string) {
	var allDecoders []string

	// generate entities for audit records
	// *AuditRecords entity and an entity for the actual audit record instance
	packet.ApplyActionToPacketDecoders(func(d packet.DecoderAPI) {
		allDecoders = append(allDecoders, d.GetName())
	})

	packet.ApplyActionToGoPacketDecoders(func(e *packet.GoPacketDecoder) {
		name := strings.ReplaceAll(e.Layer.String(), "/", "")
		allDecoders = append(allDecoders, name)
	})

	// generate maltego transform
	trx := &maltego.Transform{}
	for _, name := range allDecoders {
		path := filepath.Join(outDir, name+defaults.FileExtension)

		// stat generated profiles
		stat, err := os.Stat(path)
		if err != nil {
			log.Println("invalid path:", err, "trying", defaults.FileExtensionCompressed, "extension")

			path = filepath.Join(outDir, name+defaults.FileExtensionCompressed)
			stat, err = os.Stat(path)
			if err != nil {
				log.Println("invalid path:", err)
				continue
			}
		}
		if stat.IsDir() {
			log.Println("not a file: ", err)

			continue
		}

		// TODO: return structure from collect invocation
		// that contains the number of records per type
		// to avoid opening the file again
		numRecords, errCount := io.Count(path)
		if errCount != nil {
			log.Println("failed to count audit records:", errCount)

			continue
		}

		if numRecords == 0 {
			log.Println("no records in", path)
			continue
		}

		ent := addEntityWithPath(trx, "netcap."+name+"AuditRecords", utils.Pluralize(name), path)
		ent.AddProperty("description", "Description", maltego.Loose, name+defaults.FileExtension)
		ent.SetLinkLabel(strconv.Itoa(int(numRecords)))

		// add notes for specific audit records here
		switch name {
		//case "deviceProfile":
		//	di := "<h3>Device Profile</h3><p>Timestamp: " + time.Now().UTC().String() + "</p>"
		//	ent.AddDisplayInformation(di, "Netcap Info")
		//
		//	num, errCountRecords := io.Count(path)
		//	if errCountRecords != nil {
		//		log.Println("failed to count audit records:", errCountRecords)
		//	}
		//
		//	ent.SetNote("Storage Path: " + outDir + "\nFile Size: " + humanize.Bytes(uint64(stat.Size())) + "\nNum Profiles: " + strconv.FormatInt(num, 10) + "\nInterface: " + iface + "\nStart Time: " + start.String())
		}
	}

	time.Sleep(200 * time.Millisecond)

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
