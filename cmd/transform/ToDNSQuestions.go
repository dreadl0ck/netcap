package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap"
	maltego "github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"io"
	"log"
	"os"
	//"strconv"
	"strings"
)

// TODO: implement maltego.DNSTransform
func ToDNSQuestions() {

	lt := maltego.ParseLocalArguments(os.Args)
	dnsAuditRecords := lt.Values["path"]

	log.Println("open", dnsAuditRecords)

	f, err := os.Open(dnsAuditRecords)
	if err != nil {
		log.Println("failed to open", err)
		trx := maltego.MaltegoTransform{}
		fmt.Println(trx.ReturnOutput())
		return
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
	if header.Type != types.Type_NC_DNS {
		panic("file does not contain DNS records: " + header.Type.String())
	}

	var (
		dns = new(types.DNS)
		pm  proto.Message
		ok  bool
		trx = maltego.MaltegoTransform{}
	)
	pm = dns

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	var results = make(map[string]int)

	for {
		err := r.Next(dns)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		} else if err != nil {
			panic(err)
		}

		//log.Println("dns", dns.Context.String())

		for _, q := range dns.Questions {
			if len(q.Name) != 0 {

				// prevent duplicating results
				if _, ok := results[string(q.Name)]; ok {
					continue
				}
				results[string(q.Name)]++

				val := maltego.EscapeText(string(q.Name))

				ent := trx.AddEntity("maltego.DNSName", val)
				ent.SetType("maltego.DNSName")
				ent.SetValue(val)

				// di := "<h3>DNS Question</h3><p>Timestamp: " + dns.Timestamp + "</p>"
				// ent.AddDisplayInformation(di, "Netcap Info")

				ent.AddProperty("srcIP", "SourceIP", "strict", dns.Context.SrcIP)

				//ent.SetLinkLabel(strconv.FormatInt(dns.NumPackets, 10) + " pkts")
				ent.SetLinkColor("#000000")
				//ent.SetLinkThickness(maltego.GetThickness(ip.NumPackets))
			}
		}
	}

	trx.AddUIMessage("completed!", "Inform")
	fmt.Println(trx.ReturnOutput())
}
