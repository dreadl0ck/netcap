package transform

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	//"strconv"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/defaults"
	netio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDNSQuestions() {
	var (
		lt              = maltego.ParseLocalArguments(os.Args)
		dnsAuditRecords = lt.Values["path"]
		trx             = maltego.Transform{}
	)

	log.Println(defaultOpenCommand, dnsAuditRecords)

	f, err := os.Open(dnsAuditRecords)
	if err != nil {
		log.Println("failed to open", err)
		fmt.Println(trx.ReturnOutput())
		return
	}

	// check if its an audit record file
	if !strings.HasSuffix(f.Name(), defaults.FileExtensionCompressed) && !strings.HasSuffix(f.Name(), defaults.FileExtension) {
		trx.AddUIMessage("input file must be an audit record file", maltego.UIMessageFatal)
		fmt.Println(trx.ReturnOutput())
		log.Println("input file must be an audit record file")
		return
	}

	r, err := netio.Open(dnsAuditRecords, defaults.BufferSize)
	if err != nil {
		panic(err)
	}

	// read netcap header
	header, errFileHeader := r.ReadHeader()
	if errFileHeader != nil {
		log.Fatal(errFileHeader)
	}
	if header.Type != types.Type_NC_DNS {
		die("file does not contain DNS records", header.Type.String())
	}

	var (
		dns = new(types.DNS)
		pm  proto.Message
		ok  bool
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
				if _, exists := results[q.Name]; exists {
					continue
				}
				results[q.Name]++

				ent := trx.AddEntityWithPath("netcap.DNSName", q.Name, dnsAuditRecords)
				ent.AddProperty("srcIP", "SourceIP", maltego.Strict, dns.SrcIP)
				ent.SetLinkLabel(strconv.Itoa(results[q.Name]))
			}
		}
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
