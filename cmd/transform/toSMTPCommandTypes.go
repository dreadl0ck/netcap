/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package transform

import (
	"fmt"
	netmaltego "github.com/dreadl0ck/netcap/maltego"
	"strconv"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/types"
)

func toSMTPCommandTypes() {
	var (
		// smtp command types to number of occurrences
		commands = make(map[string]int64)
		pathName string
	)

	netmaltego.SMTPTransform(
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

	trx := &maltego.Transform{}
	for command, num := range commands {
		ent := addEntityWithPath(trx, "netcap.SMTPCommandType", command, pathName)
		ent.AddProperty("command", "Command", maltego.Strict, command)
		ent.SetLinkLabel(strconv.Itoa(int(num)))
		// TODO: num pkts / set thickness
		// ent.SetLinkThickness(maltego.GetThickness(uint64(service.BytesServer), min, max))
	}

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
