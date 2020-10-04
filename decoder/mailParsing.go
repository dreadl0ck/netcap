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
	"bufio"
	"bytes"
	"errors"
	"github.com/araddon/dateparse"
	"github.com/dreadl0ck/netcap/types"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"
	"io"
	"log"
	"net/textproto"
	"strings"
	"unicode"
)

const partIdent = "------=_Part_"

func splitMailHeaderAndBody(buf []byte) (map[string]string, string) {
	var (
		header      = make(map[string]string)
		r           = textproto.NewReader(bufio.NewReader(bytes.NewReader(buf)))
		body        string
		lastHeader  string
		collectBody bool
	)

	for {
		line, err := r.ReadLine()
		if err != nil {
			return header, body
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
			header[lastHeader] += "\n" + line

			continue
		}

		// should be an uppercase char if header field
		// multi line values start with a whitespace
		if len(parts[0]) > 0 && unicode.IsUpper(rune(parts[0][0])) {
			if parts[0] == "Envelope-To" {
				// Envelope-To means begin of email body for POP3
				collectBody = true
			}
			header[parts[0]] = strings.Join(parts[1:], ": ")
			lastHeader = parts[0]
		} else {
			// multiline
			header[lastHeader] += "\n" + line
		}
	}
}

func parseMail(parent *tcpConnection, buf []byte, from, to string, logger *log.Logger, origin string) *types.Mail {

	log.Println(ansi.Yellow, "parseMail, from:", from, "to:", to, parent.ident, "\n", string(buf), ansi.Reset)

	var (
		hdr, body = splitMailHeaderAndBody(buf)
		ti        int64
	)

	ts, err := dateparse.ParseAny(hdr["Delivery-Date"])
	if err != nil {
		decoderLog.Error("failed to parse delivery date string from mail header", zap.Error(err))
	} else {
		ti = ts.UnixNano()
	}

	// if no values provided, look in the mail header
	if from == "" || to == "" {
		from = hdr["From"]
		to = hdr["To"]
	}

	mail := &types.Mail{
		ReturnPath:      hdr["Return-Path"],
		Timestamp:       ti,
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
		Body:            parseMailParts(parent, body, logger),
		ID:              newMailID(),
		Origin:          origin,
	}

	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true

			if conf.FileStorage != "" {
				err = saveFile(parent, origin, p.Filename, nil, []byte(p.Content), []string{p.Header["Content-Transfer-Encoding"]}, parent.server.ServiceIdent(), "")
				if err != nil {
					decoderLog.Error("failed to save attachment", zap.Error(err), zap.String("origin", origin))
				}
			}

			break
		}
	}

	return mail
}

func parseMailParts(parent *tcpConnection, body string, logger *log.Logger) []*types.MailPart {
	var (
		parts        []*types.MailPart
		currentPart  *types.MailPart
		parsePayload bool
		tr           = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	logger.Println(ansi.White, "parseMailParts", parent.ident, "body:", body, ansi.Reset)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else {
				logger.Println(ansi.Yellow, parent.ident, "failed to read line: "+err.Error())

				return parts
			}
		}

		logger.Println(ansi.Green, parent.ident, "readLine", line)

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
				logger.Println(ansi.Yellow, parent.ident, "parsed header field: "+pts[0], ansi.Reset)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					logger.Println(ansi.Yellow, parent.ident, "parsed filename field: "+currentPart.Filename, ansi.Reset)
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
			logger.Println(ansi.Red, parent.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, "--"),
				Header: make(map[string]string),
			}
			logger.Println(ansi.Red, parent.ident, "start: "+currentPart.ID, ansi.Reset)

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
			logger.Println(ansi.Yellow, parent.ident, "parsed header field: "+pts[0])
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
