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

	"github.com/dreadl0ck/maltego"
)

func openLiveNetcapFolder() {
	var (
		lt                    = maltego.ParseLocalArguments(os.Args[3:])
		trx                   = &maltego.Transform{}
		openCommandName, args = createOpenCommand([]string{getPathLiveCaptureOutDir(lt.Value)})
	)

	log.Println("vals", lt.Values)
	log.Println("command for opening path:", openCommandName, args)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		maltego.Die(err.Error(), "failed to open netcap folder:\n"+string(out))
	}
	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
