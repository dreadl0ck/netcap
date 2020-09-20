package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
)

func toServiceTypes() {

	var (
		// ips to total bytes transferred (client + server)
		services = make(map[string]int64)
		auditRecordPath string
	)

	maltego.ServiceTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, service *types.Service, min, max uint64, path string, mac string, ipaddr string) {
			if auditRecordPath == "" {
				auditRecordPath = path
			}
			if service.Name != "" {
				services[service.Name] += int64(service.BytesClient + service.BytesServer)
			}
		},
		true,
	)

	trx := maltego.Transform{}
	for service, numBytes := range services {
		ent := trx.AddEntityWithPath("netcap.ServiceType", service, auditRecordPath)
		ent.SetLinkLabel(humanize.Bytes(uint64(numBytes)))
		// TODO: num pkts / set thickness
		//ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
