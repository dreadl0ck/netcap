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
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// softwareTransformationFunc is a transformation over Software profiles for a selected Software.
type softwareTransformationFunc = func(lt LocalTransform, trx *Transform, profile *types.Software, min, max uint64, path string, mac string, ip string)

// countFunc is a function that counts something over DeviceProfiles.
type softwareCountFunc = func(software *types.Software, mac string, min, max *uint64)

// SoftwareTransform applies a maltego transformation over Software profiles seen for a target Software.
func SoftwareTransform(count softwareCountFunc, transform softwareTransformationFunc) {
	var (
		lt            = ParseLocalArguments(os.Args[1:])
		softwaresFile = lt.Values["path"]
		mac           = lt.Values["mac"]
		ipaddr        = lt.Values["ipaddr"]
		stdout        = os.Stdout
		trx           = Transform{}
	)

	os.Stdout = os.Stderr
	netio.PrintBuildInfo()
	os.Stdout = stdout

	f, err := os.Open(softwaresFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		trx.AddUIMessage("input file must be an audit record file", UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		log.Println("input file must be an audit record file")
		return
	}

	r, err := netio.Open(softwaresFile, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}
	if header.Type != types.Type_NC_Software {
		panic("file does not contain Software records: " + header.Type.String())
	}

	var (
		software = new(types.Software)
		pm       proto.Message
		ok       bool
	)
	pm = software

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {
		for {
			err = r.Next(software)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			count(software, mac, &min, &max)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}

	r, err = netio.Open(softwaresFile, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	_, _ = r.ReadHeader()

	for {
		err = r.Next(software)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, software, min, max, softwaresFile, mac, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
