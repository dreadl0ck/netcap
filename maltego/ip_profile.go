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

// IPTransformationFunc is a transformation over IP profiles for a selected DeviceProfile.
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type IPTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string)

// deviceProfileCountFunc is a function that counts something over DeviceProfiles.
type ipProfileCountFunc = func(profile *types.IPProfile, mac string, min, max *uint64, ips map[string]*types.IPProfile)

// CountIPPackets returns the lowest and highest number of packets seen for a given IPProfile.
var CountIPPackets = func(profile *types.IPProfile, mac string, min, max *uint64, _ map[string]*types.IPProfile) {
	if uint64(profile.NumPackets) < *min {
		*min = uint64(profile.NumPackets)
	}
	if uint64(profile.NumPackets) > *max {
		*max = uint64(profile.NumPackets)
	}
}

// IPProfileTransformationFunc is a transformation over IP profiles
//
//goland:noinspection GoUnnecessarilyExportedIdentifiers
type IPProfileTransformationFunc = func(lt maltego.LocalTransform, trx *maltego.Transform, profile *types.IPProfile, min, max uint64, path string, mac string, ip string)

// IPProfileTransform applies a maltego transformation over IP profiles
func IPProfileTransform(count ipProfileCountFunc, transform IPProfileTransformationFunc) {
	var (
		lt     = maltego.ParseLocalArguments(os.Args[3:])
		path   = strings.TrimPrefix(lt.Values["path"], "file://")
		mac    = lt.Values["mac"]
		ipaddr = lt.Values[PropertyIpAddr]
		trx    = maltego.Transform{}
	)

	if !strings.HasPrefix(filepath.Base(path), "IPProfile.ncap") {
		path = filepath.Join(filepath.Dir(path), "IPProfile.ncap.gz")
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

	if header.Type != types.Type_NC_IPProfile {
		maltego.Die("file does not contain DeviceProfile records", header.Type.String())
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
				maltego.Die(err.Error(), errUnexpectedReadFailure)
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

// LoadIPProfiles will load the ipProfiles into memory and return them.
func LoadIPProfiles() map[string]*types.IPProfile {
	var (
		lt       = maltego.ParseLocalArguments(os.Args[3:])
		path     = filepath.Join(filepath.Dir(strings.TrimPrefix(lt.Values["path"], "file://")), "IPProfile.ncap.gz")
		profiles = make(map[string]*types.IPProfile)
		err      error
	)

	log.Println("LoadIPProfiles called")

	netio.FPrintBuildInfo(os.Stderr)
	f, path := openFile(path)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		log.Fatal("input file must be an audit record file")
	}

	r := openNetcapArchive(path)

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		maltego.Die("failed to read file header", errFileHeader.Error())
	}

	if header.Type != types.Type_NC_IPProfile {
		maltego.Die("file does not contain IPProfile records", header.Type.String())
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

	for {
		err = r.Next(profile)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			log.Println("failed to read audit records:", err)

			return profiles
		}

		profiles[profile.Addr] = &types.IPProfile{
			Addr:                   profile.Addr,
			NumPackets:             profile.NumPackets,
			Geolocation:            profile.Geolocation,
			DNSNames:               profile.DNSNames,
			TimestampFirst:         profile.TimestampFirst,
			TimestampLast:          profile.TimestampLast,
			Applications:           profile.Applications,
			Ja3Hashes:              profile.Ja3Hashes,
			Protocols:              profile.Protocols,
			Bytes:                  profile.Bytes,
			SrcPorts:               profile.SrcPorts,
			DstPorts:               profile.DstPorts,
			SNIs:                   profile.SNIs,
			Ja3FingerprintMatches:  profile.Ja3FingerprintMatches,
			Ja3SFingerprintMatches: profile.Ja3SFingerprintMatches,
		}
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	return profiles
}
