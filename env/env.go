/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package env contains static environment variable names that netcap uses.
package env

const (
	// CompletionDebug can be used to debug the commandline completions.
	CompletionDebug = "NC_COMPLETION_DEBUG"

	// ConfigRoot is the path on the filesystem that stores all netcap configuration and databases.
	ConfigRoot = "NC_CONFIG_ROOT"

	// FingerbankAPIKey is the authorization token fingerbank.org.
	FingerbankAPIKey = "FINGERBANK_API_KEY"

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

	// NetcapDBsURL is the URL for downloading netcap databases
	NetcapDBsURL = "NETCAP_DBS_URL"
)
