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
	"strings"

	"github.com/dreadl0ck/maltego"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/env"
)

func createOpenCommand(args []string) (string, []string) {
	name := os.Getenv(env.MaltegoOpenFileCommand)
	if name == "" {
		// if no command has been supplied via environment variable
		// use the platform defaults
		switch runtime.GOOS {
		case platformDarwin:
			name, args = makeDarwinOpenCommand(defaultOpenCommandDarwin, args)
		case platformWindows:
			name, args = makeWindowsOpenCommand(args)
		case platformLinux:
			name, args = makeLinuxOpenCommand(defaultOpenCommandLinux, args)
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
		case platformWindows:
			name, args = makeWindowsOpenTerminalCommand(args)
		case platformLinux:
			name, args = makeLinuxOpenTerminalCommand(defaultOpenTerminalCommandLinux, args)
		}
	} else {
		switch runtime.GOOS {
		case platformLinux:
			name, args = makeLinuxOpenTerminalCommand(name, args)
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
					filepath.Dir(strings.TrimPrefix(lt.Values["path"], "file://")),
					defaults.FileStorage,
					lt.Values["properties.contenttype"],
				),
			},
		)
	)

	log.Println("command for opening path:", openCommandName)

	out, err := exec.Command(openCommandName, args...).CombinedOutput()
	if err != nil {
		maltego.Die(err.Error(), string(out))
	}

	log.Println(string(out))

	trx.AddUIMessage("completed!", maltego.UIMessageInform)
	fmt.Println(trx.ReturnOutput())
}
