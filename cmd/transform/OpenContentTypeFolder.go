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
	"path/filepath"
	"runtime"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/env"
	"github.com/dreadl0ck/netcap/maltego"
)

func createOpenCommand(args []string) (string, []string) {
	name := os.Getenv(env.MaltegoOpenFileCommand)
	if name == "" {
		// if no command has been supplied via environment variable
		// use the platform defaults
		switch runtime.GOOS {
		case platformDarwin:
			name = defaultOpenCommandDarwin
		case platformWindows:
			name, args = makeWindowsCommand(args)
		case platformLinux:
			name, args = makeLinuxCommand(defaultOpenCommandLinux, args)
		}
	}

	log.Println("created open command:", name, args)

	return name, args
}

func createOpenTerminalCommand(args []string) (string, []string) {
	name := os.Getenv(env.MaltegoOpenTerminalCommand)
	if name == "" {
		// if no command has been supplied via environment variable
		// use the platform defaults
		switch runtime.GOOS {
		case platformDarwin:
			name = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
		case platformWindows: // TODO: open path in terminal
			name, args = makeWindowsCommand(args)
		case platformLinux: // TODO: open path in terminal
			name, args = makeLinuxCommand(defaultOpenCommandLinux, args)
		}
	}

	log.Println("command for opening path:", name, args)

	return name, args
}

func openContentTypeFolder() {
	var (
		lt                    = maltego.ParseLocalArguments(os.Args)
		trx                   = &maltego.Transform{}
		openCommandName, args = createOpenCommand(
			[]string{
				filepath.Join(
					filepath.Dir(lt.Values["path"]),
					defaults.FileStorage,
					lt.Values["properties.contenttype"],
				),
			},
		)
	)

	log.Println("command for opening path:", openCommandName)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		log.Println(string(out))
		log.Fatal(err)
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
