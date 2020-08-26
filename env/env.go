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

// Package env contains static environment variable names that netcap uses.
package env

const (
	// CompletionDebug can be used to debug the commandline completions.
	CompletionDebug = "NC_COMPLETION_DEBUG"

	// DatabaseSource is the path on the filesystem that stores all netcap databases.
	DatabaseSource = "NC_DATABASE_SOURCE"

	// FingerbankAPIKey is the authorization token fingerbank.org.
	FingerbankAPIKey = "FINGERPRINT_API_KEY"

	// MaltegoExploitDirectory is used to search for exploit PoC code.
	MaltegoExploitDirectory = "NC_MALTEGO_EXPLOIT_DIRECTORY"

	// MaltegoOpenTerminalCommand is the default terminal used when requesting to open a folder from Maltego.
	MaltegoOpenTerminalCommand = "NETCAP_MALTEGO_OPEN_TERMINAL_CMD"

	// MaltegoOpenFileCommand is the default file handler used when opening files from Maltego.
	MaltegoOpenFileCommand = "NETCAP_MALTEGO_OPEN_FILE_CMD"
)
