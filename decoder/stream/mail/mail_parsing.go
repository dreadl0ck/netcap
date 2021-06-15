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

package mail

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
	"github.com/dreadl0ck/cryptoutils"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
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

func newMailID() string {
	s, err := cryptoutils.RandomString(20)
	if err != nil {
		log.Fatal(err)
	}

	return s
}

// Parse attempts to read a mail from the conversation.
func Parse(conv *core.ConversationInfo, buf []byte, from, to string, logger *zap.SugaredLogger, origin string) *types.Mail {
	logger.Info(ansi.Yellow, "parseMail, from:", from, "to:", to, conv.Ident, "\n", string(buf), ansi.Reset)

	var (
		hdr, body = splitMailHeaderAndBody(buf)
		ti        int64
	)

	ts, err := dateparse.ParseAny(hdr["Delivery-Date"])
	if err != nil {
		mailLog.Error("failed to parse delivery date string from mail header", zap.Error(err))
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
		ContentType:     hdr["Content-Type"],
		EnvelopeTo:      hdr["Envelope-To"],
		Body:            parseMailParts(conv, body, logger),
		ID:              newMailID(),
		Origin:          origin,
	}

	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true

			if decoderconfig.Instance.FileStorage != "" {
				err = streamutils.SaveFile(conv, origin, p.Filename, nil, []byte(p.Content), []string{p.Header["Content-Transfer-Encoding"]}, conv.ServerIP+":"+strconv.Itoa(int(conv.ServerPort)), "")
				if err != nil {
					mailLog.Error("failed to save attachment", zap.Error(err), zap.String("origin", origin))
				}
			}

			break
		}
	}

	// software detection: check User-Agent header
	if ua := hdr["User-Agent"]; ua != "" {

		software.UserAgentParserMutex.Lock()

		userInfo, ok := software.UserAgentCache[ua]
		if !ok {
			userInfo = software.ParseUserAgent(ua)
			software.UserAgentCache[ua] = userInfo
			mailLog.Debug("UserAgent:", zap.String("userInfo", userInfo.Full))
		}

		software.UserAgentParserMutex.Unlock()

		if userInfo.Product != "" || userInfo.Vendor != "" || userInfo.Version != "" {
			software.WriteSoftware([]*software.AtomicSoftware{
				{
					Software: &types.Software{
						Timestamp: ti,
						Product:   userInfo.Product,
						Vendor:    userInfo.Vendor,
						Version:   userInfo.Version,
						// DeviceProfiles: []string{dpIdent},
						SourceName: "Mail UserAgent",
						SourceData: ua,
						Service:    origin,
						Flows:      []string{conv.Ident},
						Notes:      userInfo.Full,
						OS:         userInfo.OS,
					},
				},
			}, nil)
		}
	}

	// software detection: check X-Mailer header
	if xm := hdr["X-Mailer"]; xm != "" {
		if matches := software.RegexGenericVersion.FindStringSubmatch(xm); len(matches) > 0 {
			software.WriteSoftware([]*software.AtomicSoftware{
				{
					Software: &types.Software{
						Timestamp:  ti,
						Product:    strings.TrimSpace(matches[1]),
						Vendor:     strings.Split(matches[1], " ")[0],
						Version:    strings.TrimPrefix(matches[0], matches[1]),
						SourceName: "X-Mailer",
						Service:    origin,
						Flows:      []string{conv.Ident},
					},
				},
			}, nil)
		}
	}

	return mail
}

func parseMailParts(conv *core.ConversationInfo, body string, logger *zap.SugaredLogger) []*types.MailPart {
	var (
		parts        []*types.MailPart
		currentPart  *types.MailPart
		parsePayload bool
		tr           = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	logger.Info(ansi.White, "parseMailParts", conv.Ident, "body:", body, ansi.Reset)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else {
				logger.Info(ansi.Yellow, conv.Ident, "failed to read line: "+err.Error())

				return parts
			}
		}

		logger.Info(ansi.Green, conv.Ident, "readLine", line)

		if currentPart != nil {
			if parsePayload {
				// check if its an end marker for the current part
				if strings.HasSuffix(line, currentPart.ID+"--") {
					logger.Info(ansi.Cyan, "end", currentPart.ID, ansi.Reset)
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
					logger.Info(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// second type of start marker
				} else if strings.HasPrefix(line, "--") && len(line) > 25 && !strings.Contains(line, ">") {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:     strings.TrimPrefix(line, "--"),
						Header: make(map[string]string),
					}
					parsePayload = false
					logger.Info(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// its content
				} else {
					currentPart.Content += line + "\n"
					logger.Info(ansi.Blue, "adding content", line, ansi.Reset)
				}
				continue
			}
			pts := strings.Split(line, ": ")
			if len(pts) == 2 {
				currentPart.Header[pts[0]] = pts[1]
				logger.Info(ansi.Yellow, conv.Ident, "parsed header field: "+pts[0], ansi.Reset)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					logger.Info(ansi.Yellow, conv.Ident, "parsed filename field: "+currentPart.Filename, ansi.Reset)
				}
			}

			if line == "\n" || line == "" {
				parsePayload = true
				logger.Info(ansi.Green, "start parsing payload", ansi.Reset)
			}

			continue
		}
		// start marker type 1
		if strings.HasPrefix(line, partIdent) {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, partIdent),
				Header: make(map[string]string),
			}
			logger.Info(ansi.Red, conv.Ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, "--"),
				Header: make(map[string]string),
			}
			logger.Info(ansi.Red, conv.Ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}

		// single parts have no markers
		logger.Info(ansi.Red, "no marker found", line, ansi.Reset)

		currentPart = &types.MailPart{
			ID:     "none",
			Header: make(map[string]string),
		}
		pts := strings.Split(line, ": ")

		if len(pts) == 2 {
			currentPart.Header[pts[0]] = pts[1]
			logger.Info(ansi.Yellow, conv.Ident, "parsed header field: "+pts[0])
		} else {
			pts = strings.Split(line, "filename=")
			if len(pts) == 2 {
				currentPart.Filename = strings.Trim(pts[1], "\"")
				logger.Info(ansi.Yellow, "parsed filename field", currentPart.Filename, ansi.Reset)
			}
		}
		if line == "\n" || line == "" {
			parsePayload = true
			logger.Info(ansi.Green, "start parsing payload", ansi.Reset)
		}
	}

	return parts
}

func copyMailPart(part *types.MailPart) *types.MailPart {
	return &types.MailPart{
		ID:       part.ID,
		Header:   part.Header,
		Content:  part.Content,
		Filename: part.Filename,
	}
}
