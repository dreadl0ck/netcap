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

// LoadIPProfiles will load the ipProfiles into memory and return them.
func LoadIPProfiles() map[string]*types.IPProfile {
	var (
		lt       = ParseLocalArguments(os.Args[1:])
		path     = filepath.Join(filepath.Dir(lt.Values["path"]), "IPProfile.ncap.gz")
		profiles = make(map[string]*types.IPProfile)
		err error
	)

	netio.FPrintBuildInfo(os.Stderr)
	f := openPath(path)

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		log.Fatal("input file must be an audit record file")
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

	for {
		err = r.Next(profile)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			log.Println("failed to read audit records:", err)

			return profiles
		}

		profiles[profile.Addr] = &types.IPProfile{
			Addr:           profile.Addr,
			NumPackets:     profile.NumPackets,
			Geolocation:    profile.Geolocation,
			DNSNames:       profile.DNSNames,
			TimestampFirst: profile.TimestampFirst,
			TimestampLast:  profile.TimestampLast,
			Applications:   profile.Applications,
			Ja3:            profile.Ja3,
			Protocols:      profile.Protocols,
			Bytes:          profile.Bytes,
			SrcPorts:       profile.SrcPorts,
			DstPorts:       profile.DstPorts,
			SNIs:           profile.SNIs,
		}
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	return profiles
}
