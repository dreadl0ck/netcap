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
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// serviceTransformationFunc is a transformation over Service profiles for a selected Service.
type serviceTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.Service, min, max uint64, path string, mac string, ip string)

// deviceProfileCountFunc is a function that counts something over DeviceProfiles.
type serviceCountFunc = func(service *types.Service, mac string, min, max *uint64)

// ServiceTransform applies a maltego transformation over Service profiles seen for a target Service.
func ServiceTransform(count serviceCountFunc, transform serviceTransformationFunc, continueTransform bool) {
	var (
		lt     = maltego.ParseLocalArguments(os.Args[3:])
		path   = strings.TrimPrefix(lt.Values["path"], "file://")
		mac    = lt.Values["mac"]
		ipaddr = lt.Values[PropertyIpAddr]

		trx = maltego.Transform{}
	)

	if !strings.HasPrefix(filepath.Base(path), "Service.ncap") {
		path = filepath.Join(filepath.Dir(path), "Service.ncap.gz")
	}

	netio.FPrintBuildInfo(os.Stderr)

	log.Println("opening", path)

	f, err := os.Open(path)
	if err != nil {
		trx.AddUIMessage("path property not set!", maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		log.Println("input file path property not set")
		return
	}

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
	if header.Type != types.Type_NC_Service {
		maltego.Die("file does not contain Service records", header.Type.String())
	}

	var (
		service = new(types.Service)
		pm      proto.Message
		ok      bool
	)
	pm = service

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var (
		min uint64 = 10000000
		max uint64 = 0
	)

	if count != nil {
		for {
			err = r.Next(service)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count(service, mac, &min, &max)
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
		err = r.Next(service)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, service, min, max, path, mac, ipaddr)
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
