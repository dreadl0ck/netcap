package transform

import (
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toDNSQuestions() {
	results := make(map[string]int)

	maltego.DNSTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, d *types.DNS, min, max uint64, path string, ipaddr string) {
			for _, q := range d.Questions {
				if len(q.Name) != 0 {

					// prevent duplicating results
					if _, exists := results[q.Name]; exists {
						continue
					}
					results[q.Name]++

					ent := trx.AddEntityWithPath("netcap.DNSName", q.Name, path)
					ent.AddProperty("srcIP", "SourceIP", maltego.Strict, d.SrcIP)
					ent.SetLinkLabel(strconv.Itoa(results[q.Name]))
				}
			}
		},
		false,
	)
}
