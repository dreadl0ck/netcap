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

// IPTransformationFunc is a transformation over IP profiles for a selected DeviceProfile.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type IPTransformationFunc = func(lt LocalTransform, trx *Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string)

// deviceProfileCountFunc is a function that counts something over DeviceProfiles.
type ipProfileCountFunc = func(profile *types.IPProfile, mac string, min, max *uint64, ips map[string]*types.IPProfile)

// IPTransform applies a maltego transformation over IP profiles seen for a target DeviceProfile.
func IPTransform(count ipProfileCountFunc, transform IPTransformationFunc) {
	var (
		lt     = ParseLocalArguments(os.Args[1:])
		path   = lt.Values["path"]
		mac    = lt.Values["mac"]
		ipaddr = lt.Values["ipaddr"]
		trx    = Transform{}
	)

	netio.FPrintBuildInfo(os.Stderr)

	f, path := openFile(path)

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

	if header.Type != types.Type_NC_IPProfile {
		die("file does not contain IPProfile records", header.Type.String())
	}

	var (
		profile = new(types.IPProfile)
		pm      proto.Message
		ok      bool
	)

	pm = profile

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min      uint64 = 10000000
		max      uint64 = 0
		profiles        = LoadIPProfiles()
		err      error
	)

	if count != nil {
		for {
			err = r.Next(profile)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				die(err.Error(), errUnexpectedReadFailure)
			}

			count(profile, mac, &min, &max, profiles)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}
	}

	r, err = netio.Open(path, defaults.BufferSize)
	if err != nil {
		die(err.Error(), "failed to open file")
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

	trx.AddUIMessage("completed!", UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
