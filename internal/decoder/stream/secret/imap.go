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

package secret

import (
	"encoding/base64"
	"regexp"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var (
	reIMAPPlainSingle   = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\s(.*?)\s(.*?)\r\n(?:.*?)`)
	reIMATPlainSeparate = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\r\n(?:.*?)\sVXNlcm5hbWU6\r\n(.*?)\r\n(?:.*?)\sUGFzc3dvcmQ6\r\n(.*?)\r\n(?:.*?)`)
	reIMAPPlainAuth     = regexp.MustCompile(`(?:.*?)(?:AUTHENTICATE PLAIN|authenticate plain)\r\n(?:.*?)\r\n(.*?)\r\n(?:.*?)`)
	reIMAPPCramMd5      = regexp.MustCompile(`(?:.*?)AUTHENTICATE CRAM-MD5\r\n(?:.*?)\s(.*?)\r\n(.*?)\r\n(?:.*?)`)
)

// imapHarvesterFunc is the harvester function for the IMAP protocol.
func imapHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	var (
		username             string
		password             string
		serv                 string
		matchesPlainSeparate = reIMATPlainSeparate.FindSubmatch(data)
		matchesPlainSingle   = reIMAPPlainSingle.FindSubmatch(data)
		matchesLogin         = reIMAPPlainAuth.FindSubmatch(data)
		matchesCramMd5       = reIMAPPCramMd5.FindSubmatch(data)
	)

	if len(matchesPlainSingle) > 1 {
		username = string(matchesPlainSingle[1])
		password = string(matchesPlainSingle[2])
		serv = "IMAP Plain Single Line"
	}

	if len(matchesPlainSeparate) > 1 {
		usernameBin, err := base64.StdEncoding.DecodeString(string(matchesPlainSeparate[1]))
		if err != nil {
			credLog.Warn("captured IMAP credentials, but could not decode them",
				zap.Error(err),
				zap.String("input", string(matchesPlainSeparate[1])),
			)
		}
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesPlainSeparate[2]))
		if err != nil {
			credLog.Warn("captured IMAP credentials, but could not decode them",
				zap.Error(err),
				zap.String("input", string(matchesPlainSeparate[2])),
			)
		}
		username = string(usernameBin)
		password = string(passwordBin)
		serv = "IMAP Plain Separate Line"
	}

	if len(matchesLogin) > 1 {
		extractedData, err := base64.StdEncoding.DecodeString(string(matchesLogin[1]))
		if err != nil {
			credLog.Warn("captured IMAP credentials, but could not decode them",
				zap.Error(err),
				zap.String("input", string(matchesLogin[1])),
			)
		}

		var (
			newDataAuthCID  []byte
			newDataAuthZID  []byte
			newDataPassword []byte
			step            = 0
		)

		for _, b := range extractedData {
			if b == byte(0) {
				step++
			} else {
				switch step {
				case 0:
					newDataAuthCID = append(newDataAuthCID, b)
				case 1:
					newDataAuthZID = append(newDataAuthZID, b)
				case 2:
					newDataPassword = append(newDataPassword, b)
				}
			}
		}
		username = string(newDataAuthCID) + " | " + string(newDataAuthZID)
		password = string(newDataPassword)
		serv = "IMAP Login"
	}

	if len(matchesCramMd5) > 1 {
		usernameBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[1]))
		if err != nil {
			credLog.Warn("captured IMAP credentials, but could not decode them",
				zap.Error(err),
				zap.String("input", string(matchesCramMd5[1])),
			)
		}
		username = string(usernameBin) // This is really the challenge
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[2]))
		if err != nil {
			credLog.Warn("captured IMAP credentials, but could not decode them",
				zap.Error(err),
				zap.String("input", string(matchesCramMd5[2])),
			)
		}
		password = string(passwordBin) // And this is the hash
		serv = "IMAP CRAM-MD5"
	}

	if len(username) > 0 {
		return &types.Secret{
			Timestamp: ts.UnixNano(),
			Service:   serv,
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil
}

// imapHarvester is the harvester definition for IMAP
var imapHarvester = Harvester{
	Name:          "IMAP",
	Description:   "Internet Message Access Protocol - captures plaintext username and password",
	HarvesterFunc: imapHarvesterFunc,
}
