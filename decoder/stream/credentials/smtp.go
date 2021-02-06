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

package credentials

import (
	"encoding/base64"
	"time"

	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

// harvester for the SMTP protocol.
func smtpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
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
		return &types.Credentials{
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
