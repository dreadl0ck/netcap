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

package stream

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"net/textproto"
	"strconv"
	"strings"
	"unicode"

	"github.com/araddon/dateparse"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/types"
)

const partIdent = "------=_Part_"

func splitMailHeaderAndBody(buf []byte) (map[string]string, string) {
	var (
		hdr         = make(map[string]string)
		r           = textproto.NewReader(bufio.NewReader(bytes.NewReader(buf)))
		body        string
		lastHeader  string
		collectBody bool
	)

	for {
		line, err := r.ReadLine()
		if err != nil {
			return hdr, body
		}

		if collectBody {
			body += line + "\n"

			continue
		}

		if line == "" {
			// newline means begin of email body for SMTP
			collectBody = true
			continue
		}

		parts := strings.Split(line, ": ")
		if len(parts) == 0 {
			hdr[lastHeader] += "\n" + line

			continue
		}

		// should be an uppercase char if header field
		// multi line values start with a whitespace
		if len(parts[0]) > 0 && unicode.IsUpper(rune(parts[0][0])) {
			if parts[0] == "Envelope-To" {
				// Envelope-To means begin of email body for POP3
				collectBody = true
			}
			hdr[parts[0]] = strings.Join(parts[1:], ": ")
			lastHeader = parts[0]
		} else {
			// multiline
			hdr[lastHeader] += "\n" + line
		}
	}
}

func parseMail(conv *conversationInfo, buf []byte, from, to string, logger *log.Logger, origin string) *types.Mail {
	logger.Println(ansi.Yellow, "parseMail, from:", from, "to:", to, conv.ident, "\n", string(buf), ansi.Reset)

	var (
		hdr, body = splitMailHeaderAndBody(buf)
		ti        int64
	)

	ts, err := dateparse.ParseAny(hdr["Delivery-Date"])
	if err != nil {
		streamLog.Error("failed to parse delivery date string from mail header", zap.Error(err))
	} else {
		ti = ts.UnixNano()
	}

	// if no values provided, look in the mail header
	if from == "" || to == "" {
		from = hdr["From"]
		to = hdr["To"]
	}

	mail := &types.Mail{
		Timestamp:       ti,
		ReturnPath:      hdr["Return-Path"],
		DeliveryDate:    hdr["Delivery-Date"],
		From:            from,
		To:              to,
		CC:              hdr["CC"],
		Subject:         hdr["Subject"],
		Date:            hdr["Date"],
		MessageID:       hdr["Message-ID"],
		References:      hdr["References"],
		InReplyTo:       hdr["In-Reply-To"],
		ContentLanguage: hdr["Content-Language"],
		XOriginatingIP:  hdr["x-originating-ip"],
		ContentType:     hdr[headerContentType],
		EnvelopeTo:      hdr["Envelope-To"],
		Body:            parseMailParts(conv, body, logger),
		ID:              newMailID(),
		Origin:          origin,
	}

	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true

			if conf.FileStorage != "" {
				err = saveFile(conv, origin, p.Filename, nil, []byte(p.Content), []string{p.Header["Content-Transfer-Encoding"]}, conv.serverIP+":"+strconv.Itoa(int(conv.serverPort)), "")
				if err != nil {
					streamLog.Error("failed to save attachment", zap.Error(err), zap.String("origin", origin))
				}
			}

			break
		}
	}

	// software detection: check User-Agent header
	if ua := hdr["User-Agent"]; ua != "" {

		pMu.Lock()

		userInfo, ok := userAgentCaching[ua]
		if !ok {
			userInfo = parseUserAgent(ua)
			userAgentCaching[ua] = userInfo
			streamLog.Debug("UserAgent:", zap.String("userInfo", userInfo.full))
		}

		pMu.Unlock()

		if userInfo.product != "" || userInfo.vendor != "" || userInfo.version != "" {
			writeSoftware([]*software{
				{
					Software: &types.Software{
						Timestamp: ti,
						Product:   userInfo.product,
						Vendor:    userInfo.vendor,
						Version:   userInfo.version,
						// DeviceProfiles: []string{dpIdent},
						SourceName: "Mail UserAgent",
						SourceData: ua,
						Service:    origin,
						Flows:      []string{conv.ident},
						Notes:      userInfo.full,
						OS:         userInfo.os,
					},
				},
			}, nil)
		}
	}

	// software detection: check X-Mailer header
	if xm := hdr["X-Mailer"]; xm != "" {
		if matches := reGenericVersion.FindStringSubmatch(xm); len(matches) > 0 {
			writeSoftware([]*software{
				{
					Software: &types.Software{
						Timestamp:  ti,
						Product:    strings.TrimSpace(matches[1]),
						Vendor:     strings.Split(matches[1], " ")[0],
						Version:    strings.TrimPrefix(matches[0], matches[1]),
						SourceName: "X-Mailer",
						Service:    origin,
						Flows:      []string{conv.ident},
					},
				},
			}, nil)
		}
	}

	return mail
}

func parseMailParts(conv *conversationInfo, body string, logger *log.Logger) []*types.MailPart {
	var (
		parts        []*types.MailPart
		currentPart  *types.MailPart
		parsePayload bool
		tr           = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	logger.Println(ansi.White, "parseMailParts", conv.ident, "body:", body, ansi.Reset)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else {
				logger.Println(ansi.Yellow, conv.ident, "failed to read line: "+err.Error())

				return parts
			}
		}

		logger.Println(ansi.Green, conv.ident, "readLine", line)

		if currentPart != nil {
			if parsePayload {
				// check if its an end marker for the current part
				if strings.HasSuffix(line, currentPart.ID+"--") {
					logger.Println(ansi.Cyan, "end", currentPart.ID, ansi.Reset)
					parts = append(parts, copyMailPart(currentPart))
					parsePayload = false
					currentPart = nil

					// check if its the start of another part, marker type 1
				} else if strings.HasPrefix(line, partIdent) {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:     strings.TrimPrefix(line, partIdent),
						Header: make(map[string]string),
					}
					parsePayload = false
					logger.Println(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// second type of start marker
				} else if strings.HasPrefix(line, "--") && len(line) > 25 && !strings.Contains(line, ">") {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:     strings.TrimPrefix(line, "--"),
						Header: make(map[string]string),
					}
					parsePayload = false
					logger.Println(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// its content
				} else {
					currentPart.Content += line + "\n"
					logger.Println(ansi.Blue, "adding content", line, ansi.Reset)
				}
				continue
			}
			pts := strings.Split(line, ": ")
			if len(pts) == 2 {
				currentPart.Header[pts[0]] = pts[1]
				logger.Println(ansi.Yellow, conv.ident, "parsed header field: "+pts[0], ansi.Reset)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					logger.Println(ansi.Yellow, conv.ident, "parsed filename field: "+currentPart.Filename, ansi.Reset)
				}
			}

			if line == "\n" || line == "" {
				parsePayload = true
				logger.Println(ansi.Green, "start parsing payload", ansi.Reset)
			}

			continue
		}
		// start marker type 1
		if strings.HasPrefix(line, partIdent) {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, partIdent),
				Header: make(map[string]string),
			}
			logger.Println(ansi.Red, conv.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, "--"),
				Header: make(map[string]string),
			}
			logger.Println(ansi.Red, conv.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}

		// single parts have no markers
		logger.Println(ansi.Red, "no marker found", line, ansi.Reset)

		currentPart = &types.MailPart{
			ID:     "none",
			Header: make(map[string]string),
		}
		pts := strings.Split(line, ": ")

		if len(pts) == 2 {
			currentPart.Header[pts[0]] = pts[1]
			logger.Println(ansi.Yellow, conv.ident, "parsed header field: "+pts[0])
		} else {
			pts = strings.Split(line, "filename=")
			if len(pts) == 2 {
				currentPart.Filename = strings.Trim(pts[1], "\"")
				logger.Println(ansi.Yellow, "parsed filename field", currentPart.Filename, ansi.Reset)
			}
		}
		if line == "\n" || line == "" {
			parsePayload = true
			logger.Println(ansi.Green, "start parsing payload", ansi.Reset)
		}
	}

	return parts
}
