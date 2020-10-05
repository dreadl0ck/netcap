package transform

import (
	"fmt"
	"strconv"

	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSMTPCommandTypes() {
	var (
		// smtp command types to number of occurrences
		commands = make(map[string]int64)
		pathName string
	)

	maltego.SMTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, s *types.SMTP, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			for _, c := range s.Commands {
				commands[c]++
			}
		},
		true,
	)

	trx := maltego.Transform{}
	for command, num := range commands {
		ent := trx.AddEntityWithPath("netcap.SMTPCommandType", command, pathName)
		ent.AddProperty("command", "Command", maltego.Strict, command)
		ent.SetLinkLabel(strconv.Itoa(int(num)))
		// TODO: num pkts / set thickness
		// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
