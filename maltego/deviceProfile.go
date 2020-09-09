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

// countFunc is a function that counts something over DeviceProfiles.
type countFunc = func(profile *types.DeviceProfile, mac string, min, max *uint64, ips map[string]*types.IPProfile)

// deviceProfileTransformationFunc is transform over DeviceProfiles.
type deviceProfileTransformationFunc = func(lt LocalTransform, trx *Transform, profile *types.DeviceProfile, min, max uint64, path string, mac string)

// DeviceProfileTransform applies a maltego transformation DeviceProfile audit records.
func DeviceProfileTransform(count countFunc, transform deviceProfileTransformationFunc) {
	var (
		lt     = ParseLocalArguments(os.Args[1:])
		path   = lt.Values["path"]
		mac    = lt.Values["mac"]
		stdout = os.Stdout
		trx    = Transform{}
	)

	os.Stdout = os.Stderr
	netio.PrintBuildInfo()
	os.Stdout = stdout

	f, err := os.Open(path)
	if err != nil {
		// TODO: display error to user
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		trx.AddUIMessage("input file must be an audit record file", UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		log.Println("input file must be an audit record file")
		return
	}

	r, err := netio.Open(path, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}

	if header.Type != types.Type_NC_DeviceProfile {
		panic("file does not contain DeviceProfile records: " + header.Type.String())
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
	)

	if count != nil {
		for {
			err = r.Next(profile)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				panic(err)
			}

			count(profile, mac, &min, &max, profiles)
		}

		err = r.Close()
		if err != nil {
			log.Println("failed to close audit record file: ", err)
		}

		r, err = netio.Open(path, defaults.BufferSize)
		if err != nil {
			panic(err)
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

	trx.AddUIMessage("completed!", UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
