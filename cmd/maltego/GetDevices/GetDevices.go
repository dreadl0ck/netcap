package main

import (
	"flag"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"fmt"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	"strconv"

	//"strconv"
	"strings"
)

var (
	flagVersion = flag.Bool("version", false, "print version and exit")
)

func main() {

	lt := maltego.ParseLocalArguments(os.Args)
	profilesFile := lt.Values["path"]

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	//netcap.PrintBuildInfo()

	f, err := os.Open(profilesFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	var (
		//total = netcap.Count(profilesFile)
	)

	//fmt.Println("audit records", total)

	r, err := netcap.Open(profilesFile, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_DeviceProfile {
		panic("file does not contain DeviceProfile records: " + header.Type.String())
	}

	var (
		profile = new(types.DeviceProfile)
		pm  proto.Message
		ok  bool
		TRX = maltego.MaltegoTransform{}
	)
	pm = profile

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	for {
		err := r.Next(profile)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		ident := profile.MacAddr + "\n" + profile.DeviceManufacturer

		NewEnt := TRX.AddEntity("netcap.Device", ident)
		NewEnt.SetType("netcap.Device")
		NewEnt.SetValue(ident)

		di := "<h3>Heading</h3><p>Timestamp: " + profile.Timestamp + "</p>"
		NewEnt.AddDisplayInformation(di, "Other")

		NewEnt.AddProperty("path", "Path", "strict", profilesFile)
		NewEnt.AddProperty("mac", "Mac Address", "strict", profile.MacAddr)

		NewEnt.SetLinkLabel("GetDevices ("+ strconv.FormatInt(profile.NumPackets, 10)+")")
		NewEnt.SetLinkColor("#000000")
		NewEnt.SetLinkThickness(getThickness(profile.NumPackets))

		profile.DeviceIPs = nil
		profile.Contacts = nil
		note := strings.ReplaceAll(proto.MarshalTextString(profile), "\"", "'")
		note = strings.ReplaceAll(note, "<", "")
		note = strings.ReplaceAll(note, ">", "")
		NewEnt.SetNote(note)
	}

	TRX.AddUIMessage("completed!","Inform")
	fmt.Println(TRX.ReturnOutput())
}

// TODO: move into util pkg
func getThickness(val int64) int {
	switch {
	case val < 10:
		return 1
	case val < 100:
		return 2
	case val < 1000:
		return 3
	case val < 10000:
		return 4
	case val < 100000:
		return 5
	default:
		return 1
	}
}