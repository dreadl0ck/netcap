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
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// IPv6HopByHopTransformationFunc is a transformation over IPv6HopByHop audit records
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type IPv6HopByHopTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, ipv6 *types.IPv6HopByHop, min, max uint64, path string, mac string, ip string)

// IPv6HopByHopTransform applies a maltego transformation over IP profiles
func IPv6HopByHopTransform(count ipv6CountFunc, transform IPv6HopByHopTransformationFunc) {
	var (
		lt     = maltego.ParseLocalArguments(os.Args[3:])
		path   = strings.TrimPrefix(lt.Values["path"], "file://")
		mac    = lt.Values["mac"]
		ipaddr = lt.Values[PropertyIpAddr]
		trx    = maltego.Transform{}
	)

	if !strings.HasPrefix(filepath.Base(path), "IPv6HopByHop.ncap") {
		path = filepath.Join(filepath.Dir(path), "IPv6HopByHop.ncap.gz")
	}

	netio.FPrintBuildInfo(os.Stderr)

	f, path := openFile(path)

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

	if header.Type != types.Type_NC_IPv6HopByHop {
		maltego.Die("file does not contain DeviceProfile records", header.Type.String())
	}

	var (
		profile = new(types.IPv6HopByHop)
		pm      proto.Message
		ok      bool
	)

	pm = profile

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
			err = r.Next(profile)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count(mac, &min, &max)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}

	r, err = netio.Open(path, defaults.BufferSize)
	if err != nil {
		maltego.Die(err.Error(), "failed to open file")
	}

	// read netcap header - ignore err as it has been checked before
	_, _ = r.ReadHeader()

	for {
		err = r.Next(profile)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, profile, min, max, path, mac, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
