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
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// DHCPCountFunc is a function that counts something over multiple DHCP audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type DHCPCountFunc func()

// DHCPTransformationFunc is a transformation over DHCP audit records.
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type DHCPTransformationFunc = func(lt LocalTransform, trx *Transform, dhcp *types.DHCPv4, min, max uint64, path string, ip string)

// DHCPTransform applies a maltego transformation over DHCP audit records.
func DHCPTransform(count DHCPCountFunc, transform DHCPTransformationFunc, continueTransform bool) {

	var (
		lt               = ParseLocalArguments(os.Args[1:])
		path             = lt.Values["path"]
		ipaddr           = lt.Values["ipaddr"]
		dir              = filepath.Dir(path)
		dhcpAuditRecords = filepath.Join(dir, "DHCPv4.ncap.gz")
		trx              = Transform{}
	)

	f, err := os.Open(dhcpAuditRecords)
	if err != nil {
		log.Println(err)
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		trx.AddUIMessage("input file must be an audit record file", UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		log.Println("input file must be an audit record file")
		return
	}

	r, err := netio.Open(dhcpAuditRecords, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}
	if header.Type != types.Type_NC_DHCPv4 {
		panic("file does not contain DHCPv4 records: " + header.Type.String())
	}

	var (
		dhcp = new(types.DHCPv4)
		pm   proto.Message
		ok   bool
	)
	pm = dhcp

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {
		for {
			err = r.Next(dhcp)
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

	r, err = netio.Open(dhcpAuditRecords, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header - ignore err as it has been checked before
	_, _ = r.ReadHeader()

	for {
		err = r.Next(dhcp)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, dhcp, min, max, dhcpAuditRecords, ipaddr)
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
