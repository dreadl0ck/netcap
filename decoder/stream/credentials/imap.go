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

// harvester for the IMAP protocol.
func imapHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
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
