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
	"runtime"
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/env"
)

func openFileInDisassembler() {
	var (
		lt            = maltego.ParseLocalArguments(os.Args)
		trx           = &maltego.Transform{}
		loc           = strings.TrimPrefix(lt.Values["location"], "file://")
		openCmd, args = makeOpenDisasmCmd(loc)
	)

	log.Println("final command for opening file:", openCmd, args)

	// create command & run
	out, err := exec.Command(openCmd, args...).CombinedOutput()
	if err != nil {
		maltego.Die(err.Error(), "open file failed:\n"+string(out))
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}

func makeOpenDisasmCmd(loc string) (openCmd string, args []string) {
	openCmd = os.Getenv(env.MaltegoOpenDisassemblerCommand)
	if openCmd != "" {
		return openCmd, args
	}

	if openCmd == "" {
		// if no command has been supplied via environment variable
		// use the platform defaults
		switch runtime.GOOS {
		case platformDarwin:
			openCmd = findExecutable(defaultDisasmCommandMacOS, false)
			args = []string{"-e", loc}
		case platformWindows:
			openCmd = "C:\\Program Files\\IDA Freeware 7.0\\ida64.exe"
			args = []string{loc}
		case platformLinux:
			openCmd = findExecutable("ida64", false)
			args = []string{loc}
		}
	}

	return
}
