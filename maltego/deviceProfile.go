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

// CountPacketsDevices returns the lowest and highest number of packets seen for a given DeviceProfile.
var CountPacketsDevices = func(profile *types.DeviceProfile, mac string, min, max *uint64, _ map[string]*types.IPProfile) {
	if uint64(profile.NumPackets) < *min {
		*min = uint64(profile.NumPackets)
	}
	if uint64(profile.NumPackets) > *max {
		*max = uint64(profile.NumPackets)
	}
}

// CountPacketsDeviceIPs CountPacketsDevices returns the lowest and highest number of packets
// seen for all DeviceIPs of a given DeviceProfile.
var CountPacketsDeviceIPs = func(profile *types.DeviceProfile, mac string, min, max *uint64, ips map[string]*types.IPProfile) {
	if profile.MacAddr != mac {
		for _, ip := range profile.DeviceIPs {
			countIP(ips, ip, min, max)
		}
	}
}

// CountPacketsContactIPs returns the lowest and highest number of packets
// seen for all ContactIPs of a given DeviceProfile.
var CountPacketsContactIPs = func(profile *types.DeviceProfile, mac string, min, max *uint64, ips map[string]*types.IPProfile) {
	if profile.MacAddr != mac {
		return
	}
	for _, ip := range profile.Contacts {
		countIP(ips, ip, min, max)
	}
}

func countIP(ips map[string]*types.IPProfile, ip string, min, max *uint64) {
	if p, ok := ips[ip]; ok {
		if uint64(p.NumPackets) < *min {
			*min = uint64(p.NumPackets)
		}

		if uint64(p.NumPackets) > *max {
			*max = uint64(p.NumPackets)
		}
	}
}

// deviceProfileCountFunc is a function that counts something over DeviceProfiles.
type deviceProfileCountFunc = func(profile *types.DeviceProfile, mac string, min, max *uint64, ips map[string]*types.IPProfile)

// deviceProfileTransformationFunc is transform over DeviceProfiles.
type deviceProfileTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string)

// DeviceProfileTransform applies a maltego transformation DeviceProfile audit records.
func DeviceProfileTransform(count deviceProfileCountFunc, transform deviceProfileTransformationFunc) {
	var (
		lt   = maltego.ParseLocalArguments(os.Args[3:])
		path = lt.Values["path"]
		mac  = lt.Values["mac"]
		trx  = maltego.Transform{}
	)

	if !strings.HasPrefix(filepath.Base(path), "DeviceProfile.ncap") {
		path = filepath.Join(filepath.Dir(path), "DeviceProfile.ncap.gz")
	}

	netio.FPrintBuildInfo(os.Stderr)

	f, path := openFile(path)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		maltego.Die("input file must be an audit record file, but got", f.Name())
	}

	log.Println("open reader", path)
	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		maltego.Die(errFileHeader.Error(), "failed to open audit record file")
	}

	if header != nil && header.Type != types.Type_NC_DeviceProfile {
		maltego.Die("file does not contain DeviceProfile records", header.Type.String())
	}

	var (
		profile = new(types.DeviceProfile)
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
				maltego.Die(err.Error(), errUnexpectedReadFailure)
			}

			count(profile, mac, &min, &max, profiles)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}

		r, err = netio.Open(path, defaults.BufferSize)
		if err != nil {
			maltego.Die(err.Error(), "failed to open file")
		}

		// read off netcap header - ignore err as it has been checked before
		_, _ = r.ReadHeader()
	}

	for {
		err = r.Next(profile)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		transform(lt, &trx, profile, min, max, path, mac)
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
