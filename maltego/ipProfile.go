package maltego

import (
	"errors"
	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	"strings"
)

// LoadIPProfiles will load the ipProfiles at the supplied into memory and return them.
func LoadIPProfiles() map[string]*types.IPProfile {

	lt := ParseLocalArguments(os.Args[1:])
	profilesFile := lt.Values["path"]

	profiles := make(map[string]*types.IPProfile)
	stdOut := os.Stdout
	os.Stdout = os.Stderr

	f, err := os.Open(profilesFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		log.Fatal("input file must be an audit record file")
	}

	os.Stdout = stdOut

	r, err := netio.Open(profilesFile, defaults.BufferSize)
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
			panic(err)
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
			DstPorts:       profile.DstPorts,
			SrcPorts:       profile.SrcPorts,
			SNIs:           profile.SNIs,
		}
	}

	err = r.Close()
	if err != nil {
		log.Println("failed to close audit record file: ", err)
	}

	return profiles
}
