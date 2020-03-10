package main

import (
	"flag"
	"fmt"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/cmd/maltego/maltego"
	"github.com/dreadl0ck/netcap/resolvers"
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

	resolvers.InitServiceDB()

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

					for portStr, port := range ip.SrcPorts {
						ent := trx.AddEntity("netcap.SrcPort", portStr)
						ent.SetType("netcap.SrcPort")
						np, err := strconv.Atoi(portStr)
						if err != nil {
							fmt.Println(err)
							np = 0
						}

						var typ string
						if port.NumTCP > 0 {
							typ = "TCP"
						} else if port.NumUDP > 0 {
							typ = "UDP"
						}
						serviceName := resolvers.LookupServiceByPort(np, typ)
						ent.SetValue(portStr)

						di := "<h3>Port</h3><p>Timestamp: " + ip.TimestampFirst + "</p><p>ServiceName: " + serviceName +"</p>"
						ent.AddDisplayInformation(di, "Other")

						ent.AddProperty("label", "Label", "strict", portStr + "\n" + serviceName)

						ent.SetLinkLabel(strconv.FormatInt(int64(port.NumTotal), 10) + " pkts")
						ent.SetLinkColor("#000000")
						ent.SetLinkThickness(maltego.GetThickness(int64(port.NumTotal)))
					}

					break
				}
			}
			for _, ip := range profile.DeviceIPs {

				if ip.Addr == ipaddr {

					for portStr, port := range ip.SrcPorts {
						ent := trx.AddEntity("netcap.SrcPort", portStr)
						ent.SetType("netcap.SrcPort")
						np, err := strconv.Atoi(portStr)
						if err != nil {
							fmt.Println(err)
							np = 0
						}

						var typ string
						if port.NumTCP > 0 {
							typ = "TCP"
						} else if port.NumUDP > 0 {
							typ = "UDP"
						}
						serviceName := resolvers.LookupServiceByPort(np, typ)
						ent.SetValue(portStr)

						di := "<h3>Port</h3><p>Timestamp: " + ip.TimestampFirst + "</p><p>ServiceName: " + serviceName +"</p>"
						ent.AddDisplayInformation(di, "Other")

						ent.AddProperty("label", "Label", "strict", portStr + "\n" + serviceName)

						ent.SetLinkLabel(strconv.FormatInt(int64(port.NumTotal), 10) + " pkts")
						ent.SetLinkColor("#000000")
						ent.SetLinkThickness(maltego.GetThickness(int64(port.NumTotal)))
					}

					break
				}
			}
		}
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}