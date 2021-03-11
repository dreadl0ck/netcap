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

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// POP3CountFunc is a function that counts something over multiple POP3 audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type POP3CountFunc func()

// POP3TransformationFunc is a transformation over POP3 audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type POP3TransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, pop3 *types.POP3, min, max uint64, path string, ip string)

// POP3Transform applies a maltego transformation over POP3 audit records.
func POP3Transform(count POP3CountFunc, transform POP3TransformationFunc, continueTransform bool) {
	var (
		lt               = maltego.ParseLocalArguments(os.Args[3:])
		path             = lt.Values["path"]
		ipaddr           = lt.Values[PropertyIpAddr]
		dir              = filepath.Dir(path)
		pop3AuditRecords = filepath.Join(dir, "POP3.ncap.gz")
		trx              = maltego.Transform{}
	)

	f, path := openFile(pop3AuditRecords)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		maltego.Die(errUnexpectedFileType, f.Name())
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		maltego.Die("failed to read file header", errFileHeader.Error())
	}

	if header.Type != types.Type_NC_POP3 {
		maltego.Die("file does not contain POP3 records", header.Type.String())
	}

	var (
		pop3 = new(types.POP3)
		pm   proto.Message
		ok   bool
	)
	pm = pop3

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
		err error
	)

	if count != nil {
		for {
			err = r.Next(pop3)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count()
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}

	r = openNetcapArchive(path)

	// read netcap header - ignore err as it has been checked before
	_, _ = r.ReadHeader()

	for {
		err = r.Next(pop3)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, pop3, min, max, path, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	if !continueTransform {
		trx.AddUIMessage("completed!", maltego.UIMessageInform)
		fmt.Println(trx.ReturnOutput())
	}
}
