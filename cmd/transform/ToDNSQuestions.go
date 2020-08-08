package transform

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	//"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDNSQuestions() {
	lt := maltego.ParseLocalArguments(os.Args)
	dnsAuditRecords := lt.Values["path"]

	log.Println(defaultOpenCommand, dnsAuditRecords)

	f, err := os.Open(dnsAuditRecords)
	if err != nil {
		log.Println("failed to open", err)
		trx := maltego.Transform{}
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
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}
	if header.Type != types.Type_NC_DNS {
		panic("file does not contain DNS records: " + header.Type.String())
	}

	var (
		dns = new(types.DNS)
		pm  proto.Message
		ok  bool
		trx = maltego.Transform{}
	)
	pm = dns

	if _, ok = pm.(types.AuditRecord); !ok {
		panic("type does not implement types.AuditRecord interface")
	}

	results := make(map[string]int)

	for {
		err = r.Next(dns)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		} else if err != nil {
			panic(err)
		}

		// log.Println("dns", dns.Context.String())

		for _, q := range dns.Questions {
			if len(q.Name) != 0 {

				// prevent duplicating results
				if _, exists := results[string(q.Name)]; exists {
					continue
				}
				results[string(q.Name)]++

				ent := trx.AddEntity("netcap.DNSName", string(q.Name))
				ent.AddProperty("srcIP", "SourceIP", "strict", dns.Context.SrcIP)
				ent.SetLinkLabel(strconv.Itoa(results[string(q.Name)]))
			}
		}
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
