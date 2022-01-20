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
	"log"
	"os/exec"
	"runtime"
	"strings"
)

// constant defaults
const (
	// http content types.
	octetStream = "application/octet-stream"

	// darwin platform name.
	platformDarwin  = "darwin"
	platformWindows = "windows"
	platformLinux   = "linux"

	defaultDisasmCommandMacOS = "hopper"
)

// variable defaults - these can be changed during init depending on the detected platform
var (
	// default macOS command to open files from maltego.
	defaultOpenCommandDarwin = "open"

	// default linux command to open files from maltego
	// you could also set it to xdg-open.
	defaultOpenCommandLinux         = "gio"
	defaultOpenTerminalCommandLinux = "gnome-terminal"
)

// update the default linux paths for specific OSes
func initTransformTool() {
	if runtime.GOOS == platformLinux {
		out, err := exec.Command("uname", "-a").CombinedOutput()
		if err != nil {
			log.Println(err)
			return
		}
		if strings.Contains(string(out), "kali") {

			// prefer codium over xdg-open
			if path := findExecutable("codium", true); path != "" {
				defaultOpenCommandLinux = path
			} else {
				// default to use xdg-open
				defaultOpenCommandLinux = "xdg-open"
			}

			// kali uses qterminal
			defaultOpenTerminalCommandLinux = "qterminal"
		}
	}

	if runtime.GOOS == platformDarwin {
		// use visual studio code to open files if its installed
		if path := findExecutable("code", true); path != "" {
			defaultOpenCommandDarwin = path
		}
	}
}

// adds arguments for different programs to the passed in arguments.
func makeLinuxOpenCommand(commandName string, args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in

	// ensure that links are always opened with gio on linux
	if strings.HasPrefix(args[0], "https://") || strings.HasPrefix(args[0], "http://") {
		commandName = "gio"
	}

	if commandName == "gio" {
		args = append([]string{"open"}, args...)
	}

	return commandName, args
}

// adds arguments for different programs to the passed in arguments.
func makeWindowsOpenCommand(args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in
	return "cmd", append(
		[]string{"/C"},
		append(
			[]string{"start"},
			args...,
		)...,
	)
}

// adds arguments for different programs to the passed in arguments.
func makeDarwinOpenCommand(commandName string, args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in

	// ensure that links are always opened with open on macOS, so the default browser will handle them
	if strings.HasPrefix(args[0], "https://") || strings.HasPrefix(args[0], "http://") {
		commandName = "open"
	}

	return commandName, args
}

// adjust the arguments for the linux command invocation
func makeLinuxOpenTerminalCommand(commandName string, args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in

	// gnome-terminal
	// xfce4-terminal
	// mate-terminal
	// etc...
	// add the --working-directory= flag to set the path
	if strings.HasSuffix(commandName, "-terminal") {
		args = []string{"--working-directory=" + strings.Join(args, "")}
	}

	// qterminal is used in Kali Linux, use workdir flag
	if commandName == "qterminal" {
		args = []string{"--workdir=" + strings.Join(args, "")}
	}

	return commandName, args
}

// cmd.exe /K "cd /d H:\path\to\dir"
// note: /d allows to change drive letters
func makeWindowsOpenTerminalCommand(args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in
	return "cmd", append(
		[]string{"/K"},
		"cd /d "+strings.Join(args, " "),
	)
}
