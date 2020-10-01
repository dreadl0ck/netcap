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

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
)

// UDPCountFunc is a function that counts something over multiple UDP audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type UDPCountFunc func()

// UDPTransformationFunc is a transformation over UDP audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type UDPTransformationFunc = func(lt LocalTransform, trx *Transform, udp *types.UDP, min, max uint64, path string, ip string)

// UDPTransform applies a maltego transformation over UDP audit records.
func UDPTransform(count UDPCountFunc, transform UDPTransformationFunc, continueTransform bool) {
	var (
		lt     = ParseLocalArguments(os.Args[1:])
		path   = lt.Values["path"]
		ipaddr = lt.Values[PropertyIpAddr]
		trx    = Transform{}
	)

	if !strings.HasPrefix(filepath.Base(path), "UDP.ncap") {
		path = filepath.Join(filepath.Dir(path), "UDP.ncap.gz")
	}

	f, err := os.Open(path)
	if err != nil {
		log.Println(err)
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		die(errUnexpectedFileType, f.Name())
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		die("failed to read file header", errFileHeader.Error())
	}
	if header.Type != types.Type_NC_UDP {
		die("file does not contain UDP records", header.Type.String())
	}

	var (
		udp = new(types.UDP)
		pm  proto.Message
		ok  bool
	)
	pm = udp

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {
		for {
			err = r.Next(udp)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				die(err.Error(), errUnexpectedReadFailure)
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
		err = r.Next(udp)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, udp, min, max, path, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	if !continueTransform {
		trx.AddUIMessage("completed!", UIMessageInform)
		fmt.Println(trx.ReturnOutput())
	}
}