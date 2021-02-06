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
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/dreadl0ck/maltego"
)

func openNetcapFolderInTerminal() {
	var (
		lt                    = maltego.ParseLocalArguments(os.Args)
		trx                   = &maltego.Transform{}
		openCommandName, args = createOpenTerminalCommand(
			[]string{
				strings.TrimPrefix(lt.Values["path"], "file://") + ".net",
			},
		)
	)

	log.Println("vals", lt.Values)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		maltego.Die(err.Error(), string(out))
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
