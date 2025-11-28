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
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// SSHTransformationFunc is a transformation over SSH sshs for a selected SSH.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type SSHTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, ssh *types.SSH, min, max uint64, sshsFile string, mac string, ip string)

// SSHCountFunc deviceProfileCountFunc is a function that counts something over DeviceProfiles.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type SSHCountFunc = func(ssh *types.SSH, mac string, min, max *uint64)

// SSHTransform applies a maltego transformation over SSH sshs seen for a target SSH.
func SSHTransform(count SSHCountFunc, transform SSHTransformationFunc) {
	var (
		lt     = maltego.ParseLocalArguments(os.Args[3:])
		path   = strings.TrimPrefix(lt.Values["path"], "file://")
		mac    = lt.Values["mac"]
		ipaddr = lt.Values[PropertyIpAddr]

		trx = maltego.Transform{}
	)

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

	if header.Type != types.Type_NC_SSH {
		maltego.Die("file does not contain SSH records", header.Type.String())
	}

	var (
		ssh = new(types.SSH)
		pm  proto.Message
		ok  bool
	)

	pm = ssh

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
			err = r.Next(ssh)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count(ssh, mac, &min, &max)
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
		err = r.Next(ssh)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, ssh, min, max, path, mac, ipaddr)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
