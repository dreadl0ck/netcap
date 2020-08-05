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

package maltego

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/types"
)

// FilesCountFunc is a function that counts something over File audit records
type FilesCountFunc func()

// FilesTransformationFunc is a transformation over File audit records
type FilesTransformationFunc = func(lt LocalTransform, trx *Transform, file *types.File, min, max uint64, profilesFile string, ip string)

// FilesTransform applies a maltego transformation over File audit records
func FilesTransform(count FilesCountFunc, transform FilesTransformationFunc) {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	dir := filepath.Dir(profilesFile)
	httpAuditRecords := filepath.Join(dir, "File.ncap.gz")
	f, err := os.Open(httpAuditRecords)
	if err != nil {
		// write an empty reply if the audit record file was not found.
		log.Println(err)
		trx := Transform{}
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	r, err := netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}

	if header.Type != types.Type_NC_File {
		log.Fatal("file does not contain File records: " + header.Type.String())
	}

	var (
		file = new(types.File)
		pm   proto.Message
		ok   bool
		trx  = Transform{}
	)
	pm = file

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {

		for {
			err = r.Next(file)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			count()
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}

	r, err = netcap.Open(httpAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	r.ReadHeader()

	for {
		err = r.Next(file)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, file, min, max, profilesFile, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
