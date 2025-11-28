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

package credentials

import (
	"regexp"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const serviceFTP = "FTP"

var reFTP = regexp.MustCompile(`220(?:.*?)\r\n(?:.*)\r?\n?(?:.*)\r?\n?USER\s(.*?)\r\n331(?:.*?)\r\nPASS\s(.*?)\r\n`)

// ftpHarvesterFunc is the harvester function for the FTP protocol.
func ftpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Credentials {
	// harvesterDebug(ident, data, serviceFTP)

	matches := reFTP.FindSubmatch(data)
	if len(matches) > 1 {
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceFTP,
			Flow:      ident,
			User:      string(matches[1]),
			Password:  string(matches[2]),
		}
	}

	return nil
}

// ftpHarvester is the harvester definition for FTP
var ftpHarvester = Harvester{
	Name:          "FTP",
	Description:   "File Transfer Protocol - captures plaintext username and password",
	HarvesterFunc: ftpHarvesterFunc,
}
