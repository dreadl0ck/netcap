package transform

import (
	"fmt"
	"github.com/dreadl0ck/gopacket/layers"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dustin/go-humanize"
	"strconv"
)

func toSMTPCommandTypes() {

	var (
		// smtp command types to number of occurrences
		commands        = make(map[int32]int64)
		pathName string
	)

	maltego.SMTPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, s *types.SMTP, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			commands[s.Command.Command]++
		},
		true,
	)

	trx := maltego.Transform{}
	for command, num := range commands {
		ent := trx.AddEntityWithPath("netcap.SMTPCommandType", getSMTPCommandName(command), pathName)
		ent.AddProperty("code", "Code", maltego.Strict, strconv.Itoa(int(command)))
		ent.SetLinkLabel(humanize.Bytes(uint64(num)))
		// TODO: num pkts / set thickness
		//ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

// getSMTPCommandName gets a SMTPCommand string from the code
func getSMTPCommandName(command int32) string {
	switch layers.SMTPCommandType(command) {
	case layers.SMTPCommandTypeHELO:
		return "HELO"
	case layers.SMTPCommandTypeMAILFROM:
		return "MAIL FROM"
	case layers.SMTPCommandTypeRCPTTO:
		return "RCPT TO"
	case layers.SMTPCommandTypeDATA:
		return "DATA"
	case layers.SMTPCommandTypeRSET:
		return "RSET"
	case layers.SMTPCommandTypeVRFY:
		return "VRFY"
	case layers.SMTPCommandTypeNOOP:
		return "NOOP"
	case layers.SMTPCommandTypeQUIT:
		return "QUIT"
	case layers.SMTPCommandTypeEHLO:
		return "EHLO"
	case layers.SMTPCommandTypeAUTH:
		return "AUTH LOGIN"
	case layers.SMTPCommandTypeSTARTTLS:
		return "STARTTLS"
	case layers.SMTPCommandTypeSIZE:
		return "SITE"
	case layers.SMTPCommandTypeHELP:
		return "HELP"
	default:
		return "UNKNOWN"
	}
}