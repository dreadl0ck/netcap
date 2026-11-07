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
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

const serviceFTP = "FTP"

var reFTP = regexp.MustCompile(`220(?:.*?)\r\n(?:.*)\r?\n?(?:.*)\r?\n?USER\s(.*?)\r\n331(?:.*?)\r\nPASS\s(.*?)\r\n`)

// ftpHarvesterFunc is the harvester function for the FTP protocol.
func ftpHarvesterFunc(data []byte, ident string, ts time.Time) *types.Secret {
	// harvesterDebug(ident, data, serviceFTP)

	matches := reFTP.FindSubmatch(data)
	if len(matches) > 1 {
		return &types.Secret{
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

// FTPHarvesterEnabled also lets Secret-only captures select the FTP reader.
func FTPHarvesterEnabled() bool {
	if Decoder.Writer == nil || !useHarvesters {
		return false
	}
	for _, h := range tcpConnectionHarvesters {
		if h.Name == serviceFTP {
			return true
		}
	}
	return false
}

// HarvestFTPConversation is called only by the selected FTP reader. Protocol
// evidence qualifies the exchange independently of HarvesterPortFilter.
func HarvestFTPConversation(c *core.ConversationInfo) {
	if FTPHarvesterEnabled() {
		parseFTPAuth(c, WriteSecret)
	}
}

func parseFTPAuth(c *core.ConversationInfo, emit func(*types.Secret)) {
	type side struct {
		data []byte
		at   int64
		seen bool
	}
	var sides [2]side
	var pending *types.Secret
	var userAt int64
	user, upgrade, multiline := "", false, 0
	flush := func() {
		if pending != nil {
			emit(pending)
			pending = nil
		}
	}
	defer flush()
	for _, f := range c.Data {
		i := 0
		if core.FromServer(f) {
			i = 1
		}
		s := &sides[i]
		if d, ok := f.(*core.StreamData); ok && (d.DiscardedBytes > 0 || d.SkippedBytes != 0 && (d.SkippedBytes > 0 || s.seen)) {
			return
		}
		s.seen = true
		data := f.Raw()
		for len(data) > 0 {
			if len(s.data) == 0 {
				s.at = core.FragmentTime(f)
			}
			end := bytes.IndexByte(data, '\n')
			n := len(data)
			if end >= 0 {
				n = end + 1
			}
			if len(s.data)+n > 8192 {
				return
			}
			s.data = append(s.data, data[:n]...)
			data = data[n:]
			if end < 0 {
				break
			}
			line := strings.TrimSuffix(strings.TrimSuffix(string(s.data), "\n"), "\r")
			s.data = s.data[:0]
			for _, b := range []byte(line) {
				if b < 0x20 && b != '\t' || b == 0x7f {
					return
				}
			}
			if i == 1 {
				if len(line) < 4 {
					continue
				}
				code, err := strconv.Atoi(line[:3])
				if err != nil || code < 100 || code > 599 {
					continue
				}
				if multiline != 0 {
					if code != multiline || line[3] != ' ' {
						continue
					}
					multiline = 0
				} else if line[3] == '-' {
					multiline = code
					continue
				} else if line[3] != ' ' {
					continue
				}
				// Accepted AUTH: remaining bytes are TLS.
				if code == 234 {
					return
				}
				if upgrade {
					if code >= 400 {
						upgrade = false
					}
					continue
				}
				if pending != nil && (code == 230 || code >= 400) {
					pending.AuthSuccessSet, pending.AuthSuccess = true, code == 230
					flush()
				}
				if code >= 400 || code == 230 {
					user = ""
				}
				continue
			}
			if upgrade {
				continue
			}
			command, arg, _ := strings.Cut(line, " ")
			switch strings.ToUpper(command) {
			case "AUTH":
				flush()
				user = ""
				upgrade = true
			case "USER":
				flush()
				user, userAt = arg, s.at
			case "PASS":
				if user != "" {
					pending = &types.Secret{Timestamp: userAt, Service: serviceFTP, Flow: c.Ident, CommunityID: c.CommunityID, User: user, Password: arg}
					user = ""
				}
			case "REIN", "QUIT":
				flush()
				user = ""
			default:
				// A reply to another command cannot qualify this login's result.
				flush()
			}
		}
	}
}
