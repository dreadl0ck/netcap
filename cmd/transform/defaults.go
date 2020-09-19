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

const (
	// http content types.
	octetStream = "application/octet-stream"

	// darwin platform name.
	platformDarwin  = "darwin"
	platformWindows = "windows"
	platformLinux   = "linux"

	// default macOS command to open files from maltego.
	defaultOpenCommandDarwin = "open"

	// default linux command to open files from maltego
	// you could also set it to xdg-open.
	defaultOpenCommandLinux = "gio"

	defaultDisasmCommandMacOS = "/Applications/Hopper Disassembler v4.app/Contents/MacOS/hopper"
)

// adds arguments for different programs to the passed in arguments.
func makeLinuxCommand(commandName string, args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in
	if commandName == "gio" {
		args = append(args, "open")
	}

	return commandName, args
}

// adds arguments for different programs to the passed in arguments.
func makeWindowsCommand(args []string) (string, []string) { //nolint:gocritic //no named results because we want to reuse the values that have been passed in
	return "cmd", append(
		[]string{"/C"},
		append(
			[]string{"start"},
			args...,
		)...,
	)
}
