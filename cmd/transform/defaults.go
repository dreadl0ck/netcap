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
	platformDarwin = "darwin"

	// default macOS command to open files from maltego.
	defaultOpenCommand = "open"

	// default linux command to open files from maltego
	// you could also set it to xdg-open.
	defaultOpenCommandLinux = "gio"

	// Environment variables for the various OS interaction commands.
	envOpenFileCommand  = "NC_MALTEGO_OPEN_FILE_CMD"
	envExploitDirectory = "NC_MALTEGO_EXPLOIT_DIRECTORY"
)

// adds arguments for different programs to the passed in arguments.
func makeLinuxCommand(commandName string, args []string) (string, []string) {
	if commandName == "gio" {
		args = append(args, "open")
	}

	return commandName, args
}
