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
	"net/url"
	"os"
	"path/filepath"
	//"strconv"
	"strings"
)

var (
	flagVersion = flag.Bool("version", false, "print version and exit")
)

func main() {

	lt := maltego.ParseLocalArguments(os.Args)
	profilesFile := lt.Values["path"]
	ipaddr := lt.Values["ipaddr"]

	// print version and exit
	if *flagVersion {
		fmt.Println(netcap.Version)
		os.Exit(0)
	}

	dir := filepath.Dir(profilesFile)
	dnsAuditRecords := filepath.Join(dir, "HTTP.ncap.gz")
	f, err := os.Open(dnsAuditRecords)
	if err != nil {
		log.Fatal(err)
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), ".ncap.gz") && !strings.HasSuffix(f.Name(), ".ncap") {
		log.Fatal("input file must be an audit record file")
	}

	r, err := netcap.Open(dnsAuditRecords, netcap.DefaultBufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header := r.ReadHeader()
	if header.Type != types.Type_NC_HTTP {
		panic("file does not contain HTTP records: " + header.Type.String())
	}

	var (
		http = new(types.HTTP)
		pm  proto.Message
		ok  bool
		trx = maltego.MaltegoTransform{}
	)
	pm = http

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	for {
		err := r.Next(http)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		if http.SrcIP == ipaddr {
			if http.URL != "" {

				bareURL := http.Host + StripQueryString(http.URL)
				log.Println(bareURL)

				ent := trx.AddEntity("maltego.URL", bareURL)
				ent.SetType("maltego.URL")
				ent.SetValue(bareURL)

				ent.AddProperty("url", "URL", "strict", bareURL)

				di := "<h3>URL</h3><p>Timestamp: " + http.Timestamp + "</p>"
				ent.AddDisplayInformation(di, "Other")

				//ent.SetLinkLabel(strconv.FormatInt(dns..NumPackets, 10) + " pkts")
				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
			}
		}
	}

	trx.AddUIMessage("completed!","Inform")
	fmt.Println(trx.ReturnOutput())
}

func StripQueryString(inputUrl string) string {
	u, err := url.Parse(inputUrl)
	if err != nil {
		panic(err)
	}
	u.RawQuery = ""
	return u.String()
}