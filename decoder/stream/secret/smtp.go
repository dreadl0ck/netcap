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

const (
	smtpAuthPlain   = "SMTP Auth Plain"
	smtpAuthLogin   = "SMTP Auth Login"
	smtpAuthCramMd5 = "SMTP Auth CRAM-MD5"
)

var (
	reSMTPPlainSeparate = regexp.MustCompile(`(?:.*?)AUTH PLAIN\r\n334\r\n(.*?)\r\n(?:.*?)Authentication successful(?:.*?)$`)
	reSMTPPlainSingle   = regexp.MustCompile(`(?:.*?)AUTH PLAIN (.*?)\s\*\r\n235(?:.*?)`)
	reSMTPLogin         = regexp.MustCompile(`(?:.*?)AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n(.*?)\r\n334 UGFzc3dvcmQ6\r\n(.*?)\r\n235(?:.*?)`)
	reSMTPCramMd5       = regexp.MustCompile(`(?:.*?)AUTH CRAM-MD5(?:\r\n)334\s(.*?)(?:\r\n)(.*?)(\r\n)235(?:.*?)`)
)

// smtpHarvesterFunc is the harvester function for the SMTP protocol.
func smtpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	var (
		username             string
		password             string
		serv                 string
		matchesPlainSeparate = reSMTPPlainSeparate.FindSubmatch(data)
		matchesPlainSingle   = reSMTPPlainSingle.FindSubmatch(data)
		matchesLogin         = reSMTPLogin.FindSubmatch(data)
		matchesCramMd5       = reSMTPCramMd5.FindSubmatch(data)
	)

	switch {
	case len(matchesPlainSeparate) > 1:
		username, password = decodeSMTPAuthPlain(string(matchesPlainSeparate[1]))
		serv = smtpAuthPlain

	case len(matchesPlainSingle) > 1:
		username, password = decodeSMTPAuthPlain(string(matchesPlainSingle[1]))
		serv = smtpAuthPlain

	case len(matchesLogin) > 1:
		username, password = decodeSMTPLogin(matchesLogin, smtpAuthLogin)
		serv = smtpAuthLogin

	case len(matchesCramMd5) > 1:
		username, password = decodeSMTPLogin(matchesCramMd5, smtpAuthCramMd5)
		serv = smtpAuthCramMd5
	}

	if len(username) > 0 || len(password) > 0 {
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

func decodeSMTPLogin(in [][]byte, typ string) (user, pass string) {
	usernameBin, err := base64.StdEncoding.DecodeString(string(in[1]))
	if err != nil {
		credLog.Warn("captured "+typ+" credentials, but could not decode them", zap.String("input", string(in[1])))

		return
	}

	passwordBin, err := base64.StdEncoding.DecodeString(string(in[2]))
	if err != nil {
		credLog.Warn("captured credentials, but could not decode them",
			zap.String("input", string(in[2])),
			zap.String("type", typ),
		)
	}

	return string(usernameBin), string(passwordBin)
}

func decodeSMTPAuthPlain(in string) (user, pass string) {
	data, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		credLog.Warn("captured SMTP Auth Plain credentials, but could not decode them", zap.String("input", in))

		return
	}

	var (
		newDataUsername []byte
		newDataPassword []byte
		nulled          bool
	)
	for _, b := range data {
		if b == byte(0) {
			nulled = true
		} else {
			if nulled {
				newDataPassword = append(newDataPassword, b)
			} else {
				newDataUsername = append(newDataUsername, b)
			}
		}
	}

	return string(newDataUsername), string(newDataPassword)
}

// smtpHarvester is the harvester definition for SMTP
var smtpHarvester = Harvester{
	Name:          "SMTP",
	Description:   "Simple Mail Transfer Protocol - captures PLAIN, LOGIN, and CRAM-MD5 authentication",
	HarvesterFunc: smtpHarvesterFunc,
}
