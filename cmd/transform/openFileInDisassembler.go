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
	"github.com/dreadl0ck/netcap/env"
	"github.com/dreadl0ck/netcap/maltego"
	"log"
	"os"
	"os/exec"
	"runtime"
)

func openFileInDisassembler() {
	var (
		lt            = maltego.ParseLocalArguments(os.Args)
		trx           = &maltego.Transform{}
		loc           = lt.Values["location"]
		openCmd, args = makeOpenDisasmCmd(loc)
	)

	log.Println("final command for opening file:", openCmd, args)

	// create command
	cmd := exec.Command(openCmd, args...)

	// set host env
	cmd.Env = os.Environ()

	// run
	out, err := cmd.CombinedOutput()
	if err != nil {
		die(err.Error(), "open file failed:\n"+string(out))
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
			openCmd = defaultDisasmCommandMacOS
			args = []string{"-e", loc}
		case platformWindows:
			openCmd = "C:\\Program Files\\IDA Freeware 7.0\\ida64.exe"
			args = []string{loc}
		case platformLinux:
			openCmd = "ida64"
			args = []string{loc}
		}
	}

	return
}
