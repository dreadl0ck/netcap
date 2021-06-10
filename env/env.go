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

	// ConfigRoot is the path on the filesystem that stores all netcap configuration and databases.
	ConfigRoot = "NC_CONFIG_ROOT"

	// FingerbankAPIKey is the authorization token fingerbank.org.
	FingerbankAPIKey = "FINGERPRINT_API_KEY"

	// MaltegoExploitDirectory is used to search for exploit PoC code.
	MaltegoExploitDirectory = "NC_MALTEGO_EXPLOIT_DIRECTORY"

	// MaltegoOpenTerminalCommand is the default terminal used when requesting to open a folder from Maltego.
	MaltegoOpenTerminalCommand = "NETCAP_MALTEGO_OPEN_TERMINAL_CMD"

	// MaltegoOpenFileCommand is the default file handler used when opening files from Maltego.
	MaltegoOpenFileCommand = "NETCAP_MALTEGO_OPEN_FILE_CMD"

	// MaltegoOpenDisassemblerCommand can be used to overwrite the default disassembler program for your platform
	MaltegoOpenDisassemblerCommand = "NETCAP_MALTEGO_OPEN_DISASM_CMD"

	// GeoLiteAPIKey to download the geolite databases
	GeoLiteAPIKey = "NETCAP_GEOLITE_API_KEY"

	// AnalyzerDirectory contains external analyzer tools
	AnalyzerDirectory = "NETCAP_ANALYZER_DIR"
)
