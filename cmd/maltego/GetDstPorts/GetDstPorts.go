package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
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
	mac := lt.Values["mac"]
	ipaddr := lt.Values["ipaddr"]

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
		trx = maltego.MaltegoTransform{}
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

				if ip.Addr == ipaddr {

					for port, count := range ip.DstPorts {
						ent := trx.AddEntity("netcap.DstPort", port)
						ent.SetType("netcap.DstPort")
						ent.SetValue(port)

						di := "<h3>Heading</h3><p>Timestamp: " + ip.TimestampFirst + "</p>"
						ent.AddDisplayInformation(di, "Other")

						ent.SetLinkLabel(strconv.FormatInt(int64(count), 10) + " pkts")
						ent.SetLinkColor("#000000")
					}

					break
				}
			}
			for _, ip := range profile.DeviceIPs {

				if ip.Addr == ipaddr {

					for port, count := range ip.DstPorts {
						ent := trx.AddEntity("netcap.DstPort", port)
						ent.SetType("netcap.DstPort")
						ent.SetValue(port)

						di := "<h3>Heading</h3><p>Timestamp: " + ip.TimestampFirst + "</p>"
						ent.AddDisplayInformation(di, "Other")

						ent.SetLinkLabel(strconv.FormatInt(int64(count), 10) + " pkts")
						ent.SetLinkColor("#000000")
					}

					break
				}
			}
		}
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}