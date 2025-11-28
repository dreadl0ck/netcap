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

// TLSClientHelloCountFunc is a function that counts something over multiple TLSClientHello audit records.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type TLSClientHelloCountFunc func()

// TLSClientHelloTransformationFunc is a transformation over TLSClientHello audit records.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type TLSClientHelloTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, hello *types.TLSClientHello, min, max uint64, path string, ip string)

// TLSClientHelloTransform applies a maltego transformation over TLSClientHello audit records.
func TLSClientHelloTransform(count TLSClientHelloCountFunc, transform TLSClientHelloTransformationFunc) {
	var (
		lt               = maltego.ParseLocalArguments(os.Args[2:])
		path             = lt.Values["path"]
		ipaddr           = lt.Values[PropertyIpAddr]
		dir              = filepath.Dir(path)
		pop3AuditRecords = filepath.Join(dir, "TLSClientHello.ncap.gz")
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

	if header.Type != types.Type_NC_TLSClientHello {
		maltego.Die("file does not contain TLSClientHello records", header.Type.String())
	}

	var (
		tlsClientHello = new(types.TLSClientHello)
		pm             proto.Message
		ok             bool
	)
	pm = tlsClientHello

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
			err = r.Next(tlsClientHello)
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
		err = r.Next(tlsClientHello)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, tlsClientHello, min, max, path, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
