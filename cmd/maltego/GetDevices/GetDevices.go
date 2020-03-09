package main

import (
	"flag"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"fmt"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
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
		pm      proto.Message
		ok      bool
		trx     = maltego.MaltegoTransform{}
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

		ent := trx.AddEntity("netcap.Device", ident)
		ent.SetType("netcap.Device")
		ent.SetValue(ident)

		di := "<h3>Device</h3><p>Ident: "+ ident +"</p><p>MacAddr: "+ profile.MacAddr +"</p><p>DeviceManufacturer: "+ profile.DeviceManufacturer +"</p><p>Timestamp: " + profile.Timestamp + "</p>"
		ent.AddDisplayInformation(di, "Other")

		ent.AddProperty("path", "Path", "strict", profilesFile)
		ent.AddProperty("mac", "Mac Address", "strict", profile.MacAddr)

		ent.SetLinkLabel(strconv.FormatInt(profile.NumPackets, 10) + " pkts\n" + humanize.Bytes(profile.Bytes))
		ent.SetLinkColor("#000000")
		ent.SetLinkThickness(maltego.GetThickness(profile.NumPackets))
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}
