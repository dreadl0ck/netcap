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
	"net"
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
	mac := lt.Values["mac"]

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	f, err := os.Open(profilesFile)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

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

		if profile.MacAddr == mac {

			for _, ip := range profile.Contacts {

				var (
					NewEnt *maltego.MaltegoEntityObj
					addr = net.ParseIP(ip.Addr)
				)
				if addr == nil {
					fmt.Println(err)
					continue
				}
				if v4 := addr.To4(); v4 == nil {
					// v6
					NewEnt = TRX.AddEntity("maltego.IPv6Address", ip.Addr)
					NewEnt.SetType("maltego.IPv6Address")
				} else {
					NewEnt = TRX.AddEntity("maltego.IPv4Address", ip.Addr)
					NewEnt.SetType("maltego.IPv4Address")
				}
				NewEnt.SetValue(ip.Addr)

				di := "<h3>Heading</h3><p>Timestamp: " + profile.Timestamp + "</p>"
				NewEnt.AddDisplayInformation(di, "Other")

				NewEnt.AddProperty("numPackets", "Num Packets", "strict", strconv.FormatInt(profile.NumPackets, 10))

				NewEnt.SetLinkLabel("GetDeviceIPs")
				NewEnt.SetLinkColor("#000000")

				note := strings.ReplaceAll(proto.MarshalTextString(ip), "\"", "'")
				note = strings.ReplaceAll(note, "<", "")
				note = strings.ReplaceAll(note, ">", "")
				NewEnt.SetNote(note)
			}
		}
	}

	TRX.AddUIMessage("completed!","Inform")
	fmt.Println(TRX.ReturnOutput())
}