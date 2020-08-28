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

package decoder

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/dreadl0ck/netcap/logger"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

const (
	smtpAuthPlain   = "SMTP Auth Plain"
	smtpAuthLogin   = "SMTP Auth Login"
	smtpAuthCramMd5 = "SMTP Auth CRAM-MD5"
)

// credentialHarvester is a function that takes the data of a bi-directional network stream over TCP
// as well as meta information and searches for credentials in the data
// on success a pointer to a types.Credential is returned, nil otherwise.
type credentialHarvester func(data []byte, ident string, ts time.Time) *types.Credentials

var (
	useHarvesters = false

	// harvesters to be ran against all seen bi-directional communication in a TCP session
	// new harvesters must be added here in order to get called.
	tcpConnectionHarvesters = []credentialHarvester{
		ftpHarvester,
		httpHarvester,
		smtpHarvester,
		telnetHarvester,
		imapHarvester,
	}

	// mapped port number to the harvester based on the IANA standards
	// used for the first guess which harvester to use.
	harvesterPortMapping = map[int]credentialHarvester{
		21:  ftpHarvester,
		80:  httpHarvester,
		587: smtpHarvester,
		465: smtpHarvester,
		25:  smtpHarvester,
		23:  telnetHarvester,
		143: imapHarvester,
	}

	// regular expressions for the harvesters.
	reFTP               = regexp.MustCompile(`220(?:.*?)\r\n(?:.*)\r?\n?(?:.*)\r?\n?USER\s(.*?)\r\n331(?:.*?)\r\nPASS\s(.*?)\r\n`)
	reHTTPBasic         = regexp.MustCompile(`(?:.*?)HTTP(?:[\s\S]*)(?:Authorization: Basic )(.*?)\r\n`)
	reHTTPDigest        = regexp.MustCompile(`(?:.*?)Authorization: Digest (.*?)\r\n`)
	reSMTPPlainSeparate = regexp.MustCompile(`(?:.*?)AUTH PLAIN\r\n334\r\n(.*?)\r\n(?:.*?)Authentication successful(?:.*?)$`)
	reSMTPPlainSingle   = regexp.MustCompile(`(?:.*?)AUTH PLAIN (.*?)\r\n235(?:.*?)`)
	reSMTPLogin         = regexp.MustCompile(`(?:.*?)AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n(.*?)\r\n334 UGFzc3dvcmQ6\r\n(.*?)\r\n235(?:.*?)`)
	reSMTPCramMd5       = regexp.MustCompile(`(?:.*?)AUTH CRAM-MD5(?:\r\n)334\s(.*?)(?:\r\n)(.*?)(\r\n)235(?:.*?)`)
	reTelnet            = regexp.MustCompile(`(?:.*?)login:(?:.*?)(\w*?)\r\n(?:.*?)\r\nPassword:\s(.*?)\r\n(?:.*?)`)
	reIMAPPlainSingle   = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\s(.*?)\s(.*?)\r\n(?:.*?)`)
	reIMATPlainSeparate = regexp.MustCompile(`(?:.*?)(?:LOGIN|login)\r\n(?:.*?)\sVXNlcm5hbWU6\r\n(.*?)\r\n(?:.*?)\sUGFzc3dvcmQ6\r\n(.*?)\r\n(?:.*?)`)
	reIMAPPlainAuth     = regexp.MustCompile(`(?:.*?)(?:AUTHENTICATE PLAIN|authenticate plain)\r\n(?:.*?)\r\n(.*?)\r\n(?:.*?)`)
	reIMAPPCramMd5      = regexp.MustCompile(`(?:.*?)AUTHENTICATE CRAM-MD5\r\n(?:.*?)\s(.*?)\r\n(.*?)\r\n(?:.*?)`)

	// credStore is used to deduplicate the credentials written to disk
	// it maps an identifier in the format: c.Service + c.User + c.Password
	// to the flow ident where the data was observed.
	credStore   = make(map[string]string)
	credStoreMu sync.Mutex
)

//goland:noinspection GoUnusedFunction
func harvesterDebug(ident string, data []byte, args ...interface{}) {
	fmt.Println(ident, "\n", hex.Dump(data), args)
}

// harvester for the FTP protocol.
func ftpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
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

// harvester for the HTTP protocol.
func httpHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	var (
		matchesBasic  = reHTTPBasic.FindSubmatch(data)
		matchesDigest = reHTTPDigest.FindSubmatch(data)
		username      string
		password      string
	)

	if len(matchesBasic) > 1 {
		extractedData, err := base64.StdEncoding.DecodeString(string(matchesBasic[1]))
		if err != nil {
			fmt.Println("Captured HTTP Basic Auth credentials, but could not decode them")
		}
		creds := strings.Split(string(extractedData), ":")
		username = creds[0]
		password = creds[1]
	}

	if len(matchesDigest) > 1 {
		username = string(matchesDigest[1])
		password = "" // This doesn't retrieve creds per se. It retrieves the info needed to crack them
	}

	if len(username) > 1 {
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   "HTTP Basic Auth",
			Flow:      ident,
			User:      username,
			Password:  password,
		}
	}
	return nil
}

func decodeSMTPAuthPlain(in string) (user, pass string) {
	data, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		logger.DebugLog.Println("Captured SMTP Auth Plain credentials, but could not decode them")
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

func decodeSMTPLogin(in [][]byte, typ string) (user, pass string) {
	usernameBin, err := base64.StdEncoding.DecodeString(string(in[1]))
	if err != nil {
		logger.DebugLog.Println("Captured "+typ+" credentials, but could not decode them: ", string(in[1]))
	}

	passwordBin, err := base64.StdEncoding.DecodeString(string(in[2]))
	if err != nil {
		logger.DebugLog.Println("Captured "+typ+" credentials, but could not decode them: ", string(in[2]))
	}

	return string(usernameBin), string(passwordBin)
}

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

// harvester for telnet traffic.
func telnetHarvester(data []byte, ident string, ts time.Time) *types.Credentials {
	matches := reTelnet.FindSubmatch(data)
	if len(matches) > 1 {
		var username string
		for i, letter := range string(matches[1]) {
			if i%2 == 0 {
				username = username + string(letter)
			}
		}
		return &types.Credentials{
			Timestamp: ts.UnixNano(),
			Service:   serviceTelnet,
			Flow:      ident,
			User:      username,
			Password:  string(matches[2]),
		}
	}
	return nil
}

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
			logger.DebugLog.Println("Captured IMAP credentials, but could not decode them:", err, string(matchesPlainSeparate[1]))
		}
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesPlainSeparate[2]))
		if err != nil {
			logger.DebugLog.Println("Captured IMAP credentials, but could not decode them:", err, string(matchesPlainSeparate[2]))
		}
		username = string(usernameBin)
		password = string(passwordBin)
		serv = "IMAP Plain Separate Line"
	}

	if len(matchesLogin) > 1 {
		extractedData, err := base64.StdEncoding.DecodeString(string(matchesLogin[1]))
		if err != nil {
			logger.DebugLog.Println("Captured IMAP credentials, but could not decode them:", err, string(matchesLogin[1]))
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
			logger.DebugLog.Println("Captured IMAP credentials, but could not decode them:", err, string(matchesCramMd5[1]))
		}
		username = string(usernameBin) // This is really the challenge
		passwordBin, err := base64.StdEncoding.DecodeString(string(matchesCramMd5[2]))
		if err != nil {
			logger.DebugLog.Println("Captured IMAP credentials, but could not decode them:", err, string(matchesCramMd5[2]))
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

var credentialsDecoder = newCustomDecoder(
	types.Type_NC_Credentials,
	credentialsDecoderName,
	"Credentials represent a user and password combination to authenticate to a service",
	func(d *customDecoder) error {
		if conf.CustomRegex != "" {
			r, err := regexp.Compile(conf.CustomRegex)
			if err != nil {
				return err
			}

			tcpConnectionHarvesters = append(tcpConnectionHarvesters, func(data []byte, ident string, ts time.Time) *types.Credentials {
				matches := r.FindSubmatch(data)
				if len(matches) > 1 {
					notes := ""
					for _, m := range matches {
						notes += " " + string(m) + " "
					}

					return &types.Credentials{
						Notes: notes,
					}
				}

				return nil
			})
		}

		return nil
	},
	func(p gopacket.Packet) proto.Message {
		return nil
	},
	func(e *customDecoder) error {
		return nil
	},
)

// harvester for the FTP protocol
//func findVersions(data []byte, ident string, ts time.Time) *types.Software {
//
//	//harvesterDebug(ident, data, serviceFTP)
//
//	matches := reGenericVersion.FindSubmatch(data)
//	if len(matches) > 1 {
//		return &types.Software{
//			Timestamp: ts.UnixNano(),
//			Product:   string(matches[1]),
//			Version:   string(matches[2]) + "." + string(matches[3]) + "." + string(matches[4]),
//			Flows:     []string{ident},
//			Notes:     "Found by matching possible version format",
//		}
//	}
//
//	return nil
//}

// writeCredentials is a util that should be used to write credential audit to disk
// it will deduplicate the audit records to avoid repeating information on disk.
func writeCredentials(creds *types.Credentials) {
	ident := creds.Service + creds.User + creds.Password

	// prevent saving duplicate credentials
	credStoreMu.Lock()
	if _, ok := credStore[ident]; ok {
		credStoreMu.Unlock()

		return
	}

	credStore[ident] = creds.Flow
	credStoreMu.Unlock()

	if conf.ExportMetrics {
		creds.Inc()
	}

	atomic.AddInt64(&credentialsDecoder.numRecords, 1)

	err := credentialsDecoder.writer.Write(creds)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
