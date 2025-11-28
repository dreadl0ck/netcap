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
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/decoder/stream/software"
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
		// Safety check: ensure parts[0] exists and is not empty before accessing its first character
		if len(parts) > 0 && len(parts[0]) > 0 && unicode.IsUpper(rune(parts[0][0])) {
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
func Parse(conv *core.ConversationInfo, buf []byte, from, to string, logger *zap.Logger, origin string) *types.Mail {
	logger.Info("parsing mail",
		zap.String("from", from),
		zap.String("to", to),
		zap.String("ident", conv.Ident),
		zap.String("buffer", string(buf)),
	)

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

	// Perform security analysis
	secAnalysis := AnalyzeMail(mail, hdr, body)

	// Populate security fields
	mail.SPFResult = secAnalysis.SPFResult
	mail.SPFDomain = secAnalysis.SPFDomain
	mail.DKIMResult = secAnalysis.DKIMResult
	mail.DKIMDomain = secAnalysis.DKIMDomain
	mail.DMARCResult = secAnalysis.DMARCResult
	mail.DMARCPolicy = secAnalysis.DMARCPolicy
	mail.SenderDisplayNameMismatch = secAnalysis.SenderDisplayNameMismatch
	mail.HasSuspiciousReplyTo = secAnalysis.HasSuspiciousReplyTo
	mail.URLCount = secAnalysis.URLCount
	mail.AttachmentCount = secAnalysis.AttachmentCount
	mail.AttachmentTypes = secAnalysis.AttachmentTypes
	mail.HasExecutableAttachment = secAnalysis.HasExecutableAttachment
	mail.HasMacroEnabledAttachment = secAnalysis.HasMacroEnabledAttachment
	mail.SubjectEntropy = secAnalysis.SubjectEntropy
	mail.HasUrgencyKeywords = secAnalysis.HasUrgencyKeywords
	mail.ReceivedHopCount = secAnalysis.ReceivedHopCount
	mail.IsForwarded = secAnalysis.IsForwarded
	mail.ReplyTo = secAnalysis.ReplyTo
	mail.FromDomain = secAnalysis.FromDomain

	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true

			if decoderconfig.Instance.FileStorage != "" {
				// Use new file extraction framework
				extractor, ok := file.GetExtractor("MAIL")
				if !ok {
					mailLog.Error("MAIL file extractor not registered")
					break
				}

				metadata := file.FileMetadata{
					ConnectionUID: conv.Ident,
					FlowDirection: "server_to_client", // Typically receiving email
					Filename:      p.Filename,
					ContentType:   p.Header["Content-Type"],
					Host:          conv.ServerIP + ":" + strconv.Itoa(int(conv.ServerPort)),
					Encoding:      []string{p.Header["Content-Transfer-Encoding"]},
				}
				err = extractor.ExtractFile(conv, []byte(p.Content), metadata)
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
			// Safety check: extract vendor from product name
			vendor := ""
			if len(matches) > 1 {
				vendorParts := strings.Split(matches[1], " ")
				if len(vendorParts) > 0 {
					vendor = vendorParts[0]
				}
			}

			software.WriteSoftware([]*software.AtomicSoftware{
				{
					Software: &types.Software{
						Timestamp:  ti,
						Product:    strings.TrimSpace(matches[1]),
						Vendor:     vendor,
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

func parseMailParts(conv *core.ConversationInfo, body string, logger *zap.Logger) []*types.MailPart {
	var (
		parts        []*types.MailPart
		currentPart  *types.MailPart
		parsePayload bool
		tr           = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	logger.Info("parsing mail parts",
		zap.String("ident", conv.Ident),
		zap.String("body", body),
	)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else {
				logger.Info("failed to read line",
					zap.String("ident", conv.Ident),
					zap.Error(err),
				)

				return parts
			}
		}

		logger.Info("read line",
			zap.String("ident", conv.Ident),
			zap.String("line", line),
		)

		if currentPart != nil {
			if parsePayload {
				// check if its an end marker for the current part
				if strings.HasSuffix(line, currentPart.ID+"--") {
					logger.Info("mail part end",
						zap.String("part_id", currentPart.ID),
					)
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
					logger.Info("mail part start",
						zap.String("part_id", currentPart.ID),
					)

					// second type of start marker
				} else if strings.HasPrefix(line, "--") && len(line) > 25 && !strings.Contains(line, ">") {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:     strings.TrimPrefix(line, "--"),
						Header: make(map[string]string),
					}
					parsePayload = false
					logger.Info("mail part start",
						zap.String("part_id", currentPart.ID),
					)

					// its content
				} else {
					currentPart.Content += line + "\n"
					logger.Info("adding content to mail part",
						zap.String("line", line),
					)
				}
				continue
			}
			pts := strings.Split(line, ": ")
			if len(pts) == 2 {
				currentPart.Header[pts[0]] = pts[1]
				logger.Info("parsed header field",
					zap.String("ident", conv.Ident),
					zap.String("field", pts[0]),
				)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					logger.Info("parsed filename field",
						zap.String("ident", conv.Ident),
						zap.String("filename", currentPart.Filename),
					)
				}
			}

			if line == "\n" || line == "" {
				parsePayload = true
				logger.Info("start parsing payload")
			}

			continue
		}
		// start marker type 1
		if strings.HasPrefix(line, partIdent) {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, partIdent),
				Header: make(map[string]string),
			}
			logger.Info("mail part start",
				zap.String("ident", conv.Ident),
				zap.String("part_id", currentPart.ID),
			)

			continue
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, "--"),
				Header: make(map[string]string),
			}
			logger.Info("mail part start",
				zap.String("ident", conv.Ident),
				zap.String("part_id", currentPart.ID),
			)

			continue
		}

		// single parts have no markers
		logger.Info("no marker found",
			zap.String("line", line),
		)

		currentPart = &types.MailPart{
			ID:     "none",
			Header: make(map[string]string),
		}
		pts := strings.Split(line, ": ")

		if len(pts) == 2 {
			currentPart.Header[pts[0]] = pts[1]
			logger.Info("parsed header field",
				zap.String("ident", conv.Ident),
				zap.String("field", pts[0]),
			)
		} else {
			pts = strings.Split(line, "filename=")
			if len(pts) == 2 {
				currentPart.Filename = strings.Trim(pts[1], "\"")
				logger.Info("parsed filename field",
					zap.String("filename", currentPart.Filename),
				)
			}
		}
		if line == "\n" || line == "" {
			parsePayload = true
			logger.Info("start parsing payload")
		}
	}

	// Handle any remaining currentPart that wasn't closed with an end marker
	if currentPart != nil && (currentPart.Content != "" || len(currentPart.Header) > 0) {
		parts = append(parts, copyMailPart(currentPart))
	}

	return parts
}

func copyMailPart(part *types.MailPart) *types.MailPart {
	return &types.MailPart{
		ID:     part.ID,
		Header: part.Header,
		// Sanitize content to ensure valid UTF-8 for proto encoding
		// Proto3 string fields require valid UTF-8, but email content
		// may contain binary data or non-UTF-8 encoded text
		Content:  strings.ToValidUTF8(part.Content, "�"),
		Filename: part.Filename,
	}
}
