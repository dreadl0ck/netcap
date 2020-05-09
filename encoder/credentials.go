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

package encoder

import (
	"encoding/base64"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

// CredentialHarvester is a function that takes the data of a bi-directional network stream over TCP
// as well as meta information and searches for credentials in the data
// on success a pointer to a types.Credential is returned, nil otherwise
type CredentialHarvester func(data []byte, ident string, ts time.Time) *types.Credentials

// harvesters to be ran against all seen bi-directional communication in a TCP session
var tcpConnectionHarvesters = []CredentialHarvester{
	ftpHarvester,
}

// FTP protocol
var ftpCredentialsRegex, errFtpRegex = regexp.Compile("220(.*)\\r\\nUSER\\s(.*)\\r\\n331(.*)\\r\\nPASS\\s(.*)\\r\\n")

var (
	reFTP               = regexp.MustCompile(`220(?:.*?)\r\nUSER\s(.*?)\r\n331(?:.*?)\r\nPASS\s(.*?)\r\n`)
	reHTTPBasic         = regexp.MustCompile(`(?:.*?)HTTP(?:[\s\S]*)(?:Authorization: Basic )(.*?)\r\n`)
	reHTTPDigest        = regexp.MustCompile(`(?:.*?)Authorization: Digest (.*?)\r\n`)
	reSMTPPlainSeparate = regexp.MustCompile(`(?:.*?)AUTH PLAIN\r\n334\r\n(.*?)\r\n(?:.*?)Authentication successful(?:.*?)$`)
	reSMTPPlainSingle   = regexp.MustCompile(`(?:.*?)AUTH PLAIN (.*?)\r\n(?:.*?)Authentication successful(?:.*?)$`)
	reSMTPLogin         = regexp.MustCompile(`(?:.*?)AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n(.*?)\r\n334 UGFzc3dvcmQ6\r\n(.*?)\r\n235(?:.*?)Authentication successful(?:.*?)$`)
	reSMTPCramMd5       = regexp.MustCompile(`(?:.*?)AUTH CRAM-MD5(?:\r\n)334\s(.*?)(?:\r\n)(.*?)(\r\n)235(?:.*?)Authentication successful(?:.*?)$`)
	reTelnet            = regexp.MustCompile(`(?:.*?)login:\s(.*?)\r\n(?:.*?)\r\nPassword:\s(.*?)\r\n(?:.*?)`)
	reIMAPPlainSingle   = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\s(.*?)\s(.*?)\r\n(?:.*?)Logged in(?:.*?)$`)
	reIMATPlainSeparate = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\r\n(?:.*?)\sVXNlcm5hbWU6\r\n(.*?)\r\n(?:.*?)\sUGFzc3dvcmQ6\r\n(.*?)\r\n(?:.*?)Logged in(?:.*?)$`)
	reIMAPPlainAuth     = regexp.MustCompile(`(?:.*?)(?:AUTHENTICATE PLAIN|authenticate plain)\r\n(?:.*?)\r\n(.*?)\r\n(?:.*?)Logged in(?:.*?)$`)
	reIMAPPCramMd5      = regexp.MustCompile(`(?:.*?)AUTHENTICATE CRAM-MD5\r\n(?:.*?)\s(.*?)\r\n(.*?)\r\n(?:.*?)authentication successful(?:.*?)$`)
)

func ftpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	matches := reFTP.FindSubmatch(data)
	if len(matches) > 1 {
		username := string(matches[1])
		password := string(matches[2])
		return &types.Credentials{
			Timestamp: ts.String(),
			Service:   "FTP",
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}

	return nil
}

func httpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	matchesBasic := reHTTPBasic.FindSubmatch(data)
	matchesDigest := reHTTPDigest.FindSubmatch(data)
	var username string
	var password string

	if len(matchesBasic) > 1 {
		data, err := base64.StdEncoding.DecodeString(string(matchesBasic[1]))
		if err != nil {
			fmt.Println("Captured HTTP Basic Auth credentials, but could not decode them")
		}
		creds := strings.Split(string(data), ":")
		username = creds[0]
		password = creds[1]
	}

	if len(matchesDigest) > 1 {
		username = string(matchesDigest[1])
		password = "" // This doesn't retrieve creds per se. It retrieves the info needed to crack them
	}

	if len(username) > 1 {
		return &types.Credentials{
			Timestamp: ts.String(),
			Service:   "HTTP Basic Auth",
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil
}

func smtpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	var username string
	var password string
	var service string
	matchesPlainSeparate := reSMTPPlainSeparate.FindSubmatch(data)
	matchesPlainSingle := reSMTPPlainSingle.FindSubmatch(data)
	matchesLogin := reSMTPLogin.FindSubmatch(data)
	matchesCramMd5 := reSMTPCramMd5.FindSubmatch(data)

	if len(matchesPlainSeparate) > 1 {
		data, err := base64.StdEncoding.DecodeString(string(matchesPlainSeparate[1]))
		if err != nil {
			fmt.Println("Captured SMTP Auth Plain credentials, but could not decode them")
		}
		var newDataUsername []byte
		var newDataPassword []byte
		var nulled bool = false
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
		username = string(newDataUsername)
		password = string(newDataPassword)
		service = "SMTP Auth Plain"
	}

	if len(matchesPlainSingle) > 1 {
		data, err := base64.StdEncoding.DecodeString(string(matchesPlainSingle[1]))
		if err != nil {
			fmt.Println("Captured SMTP Auth Plain credentials, but could not decode them")
		}
		var newDataUsername []byte
		var newDataPassword []byte
		var nulled bool = false
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
		username = string(newDataUsername)
		password = string(newDataPassword)
		service = "SMTP Auth Plain"
	}

	if len(matchesLogin) > 1 {
		usernameBin, err := base64.StdEncoding.DecodeString(string(matchesLogin[1]))
		if err != nil {
			fmt.Println("Captured SMTP Auth Login credentials, but could not decode them")
		}
		username = string(usernameBin)
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesLogin[2]))
		if err != nil {
			fmt.Println("Captured SMTP Auth Login credentials, but could not decode them")
		}
		password = string(passwordBin)
		service = "SMTP Auth Login"
	}

	if len(matchesCramMd5) > 1 {
		usernameBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[1]))
		if err != nil {
			fmt.Println("Captured SMTP CARM-MD5 credentials, but could not decode them")
		}
		username = string(usernameBin) // This is really the challenge
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[2]))
		if err != nil {
			fmt.Println("Captured SMTP CARM-MD5 credentials, but could not decode them")
		}
		password = string(passwordBin) // And this is the hash
		service = "SMTP Auth CRAM-MD5"
	}

	if len(username) > 0 {
		return &types.Credentials{
			Timestamp: ts.String(),
			Service:   service,
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil
}

func telnetHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	matches := reTelnet.FindSubmatch(data)
	if len(matches) > 1 {
		userWrong := string(matches[1])
		var username string
		for i, letter := range userWrong {
			if i%2 == 0 {
				username = username + string(letter)
			}
		}
		password := string(matches[2])
		return &types.Credentials{
			Timestamp: ts.String(),
			Service:   "Telnet",
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil
}

func imapHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	var username string
	var password string
	matchesPlainSeparate := reIMATPlainSeparate.FindSubmatch(data)
	matchesPlainSingle := reIMAPPlainSingle.FindSubmatch(data)
	matchesLogin := reIMAPPlainAuth.FindSubmatch(data)
	matchesCramMd5 := reIMAPPCramMd5.FindSubmatch(data)

	if len(matchesPlainSingle) > 1 {
		username = string(matchesPlainSingle[1])
		password = string(matchesPlainSingle[2])
	}

	if len(matchesPlainSeparate) > 1 {
		usernameBin, err := base64.StdEncoding.DecodeString(string(matchesPlainSeparate[1]))
		if err != nil {
			fmt.Println("Captured IMAP credentials, but could not decode them")
		}
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesPlainSeparate[2]))
		if err != nil {
			fmt.Println("Captured IMAP credentials, but could not decode them")
		}
		username = string(usernameBin)
		password = string(passwordBin)
	}

	if len(matchesLogin) > 1 {
		data, err := base64.StdEncoding.DecodeString(string(matchesLogin[1]))
		if err != nil {
			fmt.Println("Captured IMAP credentials, but could not decode them")
		}
		var newDataAuthCID []byte
		var newDataAuthZID []byte
		var newDataPassword []byte
		var step int = 0
		for _, b := range data {
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
	}

	if len(matchesCramMd5) > 1 {
		usernameBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[1]))
		if err != nil {
			fmt.Println("Captured IMAP credentials, but could not decode them")
		}
		username = string(usernameBin) // This is really the challenge
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[2]))
		if err != nil {
			fmt.Println("Captured IMAP credentials, but could not decode them")
		}
		password = string(passwordBin) // And this is the hash
	}

	if len(username) > 0 {
		return &types.Credentials{
			Timestamp: ts.String(),
			Service:   "IMAP",
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil

}

var credentialsEncoder = CreateCustomEncoder(types.Type_NC_Credentials, "Credentials", func(d *CustomEncoder) error {

	// credential encoder init: check errors from compiling harvester regexes here
	if errFtpRegex != nil {
		return errFtpRegex
	}

	return nil
}, func(p gopacket.Packet) proto.Message {
	return nil
}, func(e *CustomEncoder) error {
	return nil
})

// credStore is used to deduplicate the credentials written to disk
// it maps an identifier in the format: c.Service + c.User + c.Password
// to the flow ident where the data was observed
var credStore = make(map[string]string)

// writeCredentials is a util that should be used to write credential audit to disk
// it will deduplicate the audit records to avoid repeating information on disk
func writeCredentials(c *types.Credentials) {

	ident := c.Service + c.User + c.Password

	// prevent saving duplicate credentials
	if _, ok := credStore[ident]; ok {
		return
	}
	credStore[ident] = c.Flow

	if credentialsEncoder.export {
		c.Inc()
	}

	atomic.AddInt64(&credentialsEncoder.numRecords, 1)
	err := credentialsEncoder.writer.Write(c)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
