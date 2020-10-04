package transform

import (
	"fmt"
	"github.com/dreadl0ck/netcap/maltego"
	"github.com/dreadl0ck/netcap/types"
	"strconv"
	"strings"
)

func toTCPFlagCombinations() {
	var (
		idents   = make(map[string]int)
		pathName string
	)

	maltego.TCPTransform(
		nil,
		func(lt maltego.LocalTransform, trx *maltego.Transform, tcp *types.TCP, min, max uint64, path string, ipaddr string) {
			if pathName == "" {
				pathName = path
			}
			idents[tcpFlagsToString(tcp)]++
		},
		true,
	)

	trx := maltego.Transform{}
	for flags, numHits := range idents {
		ent := trx.AddEntityWithPath("netcap.TCPFlag", flags, pathName)
		ent.SetLinkLabel(strconv.Itoa(numHits))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

func tcpFlagsToString(tcp *types.TCP) string {

	var arr = make([]string, 0, 9)

	if tcp.FIN {
		arr = append(arr, "FIN")
	}

	if tcp.SYN {
		arr = append(arr, "SYN")
	}

	if tcp.RST {
		arr = append(arr, "RST")
	}

	if tcp.PSH {
		arr = append(arr, "PSH")
	}

	if tcp.ACK {
		arr = append(arr, "ACK")
	}

	if tcp.URG {
		arr = append(arr, "URG")
	}

	if tcp.ECE {
		arr = append(arr, "ECE")
	}

	if tcp.CWR {
		arr = append(arr, "CWR")
	}

	if tcp.NS {
		arr = append(arr, "NS")
	}

	return strings.Join(arr, ",")
}
