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
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/araddon/dateparse"
	"github.com/dreadl0ck/cryptoutils"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"
	"io"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

/*
 * SMTP protocol
 */

// smtpState describes a state in the SMTP state machine.
type smtpState int

const (
	smtpStateNotAuthenticated smtpState = iota
	smtpStateAuthenticated
	// StateNotIdentified
	// StateDataTransfer

	serviceSMTP = "SMTP"
)

const (
	// SMTP client commands
	smtpDot       = "."
	smtpHELO      = "HELO"
	smtpMAILFROM  = "MAIL FROM"
	smtpRCPTTO    = "RCPT TO"
	smtpDATA      = "DATA"
	smtpRSET      = "RSET"
	smtpVRFY      = "VRFY"
	smtpNOOP      = "NOOP"
	smtpQUIT      = "QUIT"
	smtpEHLO      = "EHLO"
	smtpAUTHLOGIN = "AUTH LOGIN"
	smtpSTARTTLS  = "STARTTLS"
	smtpSITE      = "SITE"
	smtpHELP      = "HELP"

	// SMTP logging operations
	opSMTPSave     = "SMTP-save"
	opSMTPResponse = "SMTP-response"

	// server response codes
	smtpOK                      = 200 // (nonstandard success response, see rfc876)
	smtpStatus                  = 211 // System status, or system help reply
	smtpHelp                    = 214 // Help message
	smtpServiceReady            = 220 // <domain> Service ready
	smtpServiceClosing          = 221 // <domain> Service closing transmission channel
	smtpMailActionCompleted     = 250 // Requested mail action okay, completed
	smtpUserNotLocal            = 251 // User not local; will forward to <forward-path>
	smtpCannotVerify            = 252 // Cannot VRFY user, but will accept message and attempt delivery
	smtpStartMail               = 354 // Start mail input; end with <CRLF>.<CRLF>
	smtpServiceUnavailable      = 421 // <domain> Service not available, closing transmission channel
	smtpMailboxUnavailable      = 450 // Requested mail action not taken: mailbox unavailable
	smtpLocalError              = 451 // Requested action aborted: local error in processing
	smtpInsufficientStorage     = 452 // Requested action not taken: insufficient system storage
	smtpSyntaxError             = 500 // Syntax error, command unrecognised
	smtpArgumentSyntaxError     = 501 // Syntax error in parameters or arguments
	smtpCmdNotImplemented       = 502 // Command not implemented
	smtpBadSequence             = 503 // Bad sequence of commands
	smtpParameterNotImplemented = 504 // Command parameter not implemented
	smtpMailNotAccepted         = 521 // <domain> does not accept mail (see rfc1846)
	smtpAccessDenied            = 530 // Access denied (???a Sendmailism)
	smtpErrActionNotTaken       = 550 // Requested action not taken: mailbox unavailable
	smtpErrUserNotLocal         = 551 // User not local; please try <forward-path>
	smtpExceededStorage         = 552 // Requested mail action aborted: exceeded storage allocation
	smtpMailboxNotAllowed       = 553 // Requested action not taken: mailbox name not allowed
	smtpTransactionFailed       = 554 // Transaction failed
)

type smtpReader struct {
	parent *tcpConnection

	smtpRequests  []*types.SMTPRequest
	smtpResponses []*types.SMTPResponse
	reqIndex      int
	resIndex      int

	user, pass, token string
}

func validSMTPCommand(cmd string) bool {

	switch cmd {
	case smtpDot,
		smtpHELO,
		smtpMAILFROM,
		smtpRCPTTO,
		smtpDATA,
		smtpRSET,
		smtpVRFY,
		smtpNOOP,
		smtpQUIT,
		smtpEHLO,
		smtpAUTHLOGIN,
		smtpSTARTTLS,
		smtpSITE,
		smtpHELP:
		return true
	default:
		return false
	}
}

// Decode parses the stream according to the SMTP protocol.
func (h *smtpReader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if smtpDecoder.writer == nil {
		return
	}

	decodeTCPConversation(
		h.parent,
		func(b *bufio.Reader) error {
			return h.readRequest(b)
		},
		func(b *bufio.Reader) error {
			return h.readResponse(b)
		},
	)

	var commands []string

	for _, c := range h.smtpRequests {
		commands = append(commands, c.Command)
	}

	smtpDebug(ansi.LightGreen, serviceSMTP, h.parent.ident, "requests", len(h.smtpRequests), "responses", len(h.smtpResponses), ansi.Reset)

	mails := h.parseMails()

	smtpMsg := &types.SMTP{
		Timestamp: h.parent.firstPacket.UnixNano(),
		SrcIP:     h.parent.net.Src().String(),
		DstIP:     h.parent.net.Dst().String(),
		SrcPort:   utils.DecodePort(h.parent.transport.Src().Raw()),
		DstPort:   utils.DecodePort(h.parent.transport.Dst().Raw()),
		MailIDs:   mails,
		Commands:  commands,
	}

	// export metrics if configured
	if conf.ExportMetrics {
		smtpMsg.Inc()
	}

	// write record to disk
	atomic.AddInt64(&smtpDecoder.numRecords, 1)

	err := smtpDecoder.writer.Write(smtpMsg)
	if err != nil {
		errorMap.Inc(err.Error())
	}
}

func (h *smtpReader) saveFile(source, name string, err error, body []byte, encoding []string, host string) error {

	decoderLog.Info("smtpReader.saveFile",
		zap.String("source", source),
		zap.String("name", name),
		zap.Error(err),
		zap.Int("bodyLength", len(body)),
		zap.Strings("encoding", encoding),
		zap.String("host", host),
	)

	// prevent saving zero bytes
	if len(body) == 0 {
		return nil
	}

	if name == "" || name == "/" {
		name = "unknown"
	}

	var (
		fileName string

		// detected content type
		cType = trimEncoding(http.DetectContentType(body))

		// root path
		root = path.Join(conf.Out, conf.FileStorage, cType)

		// file extension
		ext = fileExtensionForContentType(cType)

		// file basename
		base = filepath.Clean(name+"-"+path.Base(utils.CleanIdent(h.parent.ident))) + ext
	)

	if err != nil {
		base = "incomplete-" + base
	}

	if filepath.Ext(name) == "" {
		fileName = name + ext
	} else {
		fileName = name
	}

	// make sure root path exists
	err = os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		decoderLog.Error("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
		)
	}

	base = path.Join(root, base)

	if len(base) > 250 {
		base = base[:250] + "..."
	}

	if base == conf.FileStorage {
		base = path.Join(conf.Out, conf.FileStorage, "noname")
	}

	var (
		target = base
		n      = 0
	)

	for {
		_, errStat := os.Stat(target)
		if errStat != nil {
			break
		}

		if err != nil {
			target = path.Join(root, filepath.Clean("incomplete-"+name+"-"+utils.CleanIdent(h.parent.ident))+"-"+strconv.Itoa(n)+fileExtensionForContentType(cType))
		} else {
			target = path.Join(root, filepath.Clean(name+"-"+utils.CleanIdent(h.parent.ident))+"-"+strconv.Itoa(n)+fileExtensionForContentType(cType))
		}

		n++
	}

	// fmt.Println("saving file:", target)

	f, err := os.Create(target)
	if err != nil {
		logReassemblyError("SMTP-create", fmt.Sprintf("cannot create %s", target), err)

		return err
	}

	// explicitly declare io.Reader interface
	var (
		r             io.Reader
		length        int
		hash          string
		cTypeDetected = trimEncoding(http.DetectContentType(body))
	)

	// now assign a new buffer
	r = bytes.NewBuffer(body)

	// Decode gzip
	if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
		r, err = gzip.NewReader(r)
		if err != nil {
			logReassemblyError("SMTP-gunzip", "Failed to gzip decode: %s", err)
		}
	}

	// Decode base64
	if len(encoding) > 0 && (encoding[0] == "base64") {
		r, _ = base64.NewDecoder(base64.StdEncoding, r).(io.Reader)
	}

	if err == nil {
		w, errCopy := io.Copy(f, r)
		if errCopy != nil {
			logReassemblyError(opSMTPSave, fmt.Sprintf("%s: failed to save %s (l:%d)", h.parent.ident, target, w), errCopy)
		} else {
			reassemblyLog.Debug("saved SMTP data",
				zap.String("ident", h.parent.ident),
				zap.String("target", target),
				zap.Int64("written", w),
			)
		}

		if _, ok := r.(*gzip.Reader); ok {
			errClose := r.(*gzip.Reader).Close()
			if errClose != nil {
				logReassemblyError(opSMTPSave, fmt.Sprintf("%s: failed to close gzip reader %s (l:%d)", h.parent.ident, target, w), errClose)
			}
		}

		errClose := f.Close()
		if errClose != nil {
			logReassemblyError(opSMTPSave, fmt.Sprintf("%s: failed to close file handle %s (l:%d)", h.parent.ident, target, w), errClose)
		}

		// TODO: refactor to avoid reading the file contents into memory again
		body, err = ioutil.ReadFile(target)
		if err == nil {
			// set hash to value for decompressed content and update size
			hash = hex.EncodeToString(cryptoutils.MD5Data(body))
			length = len(body)

			// update content type
			cTypeDetected = trimEncoding(http.DetectContentType(body))

			// make sure root path exists
			createContentTypePathIfRequired(path.Join(conf.Out, conf.FileStorage, cTypeDetected))

			// switch the file extension and the path for the updated content type
			ext = filepath.Ext(target)

			// create new target: trim extension from old one and replace
			// and replace the old content type in the path
			newTarget := strings.Replace(strings.TrimSuffix(target, ext), cType, cTypeDetected, 1) + fileExtensionForContentType(cTypeDetected)

			err = os.Rename(target, newTarget)
			if err == nil {
				target = newTarget
			} else {
				fmt.Println("failed to rename file after decompression", err)
			}
		}
	} else {
		hash = hex.EncodeToString(cryptoutils.MD5Data(body))
		length = len(body)
	}

	// write file to disk
	writeFile(&types.File{
		Timestamp:           h.parent.firstPacket.UnixNano(),
		Name:                fileName,
		Length:              int64(length),
		Hash:                hash,
		Location:            target,
		Ident:               h.parent.ident,
		Source:              source,
		ContentType:         cType,
		ContentTypeDetected: cTypeDetected,
		SrcIP:               h.parent.net.Src().String(),
		DstIP:               h.parent.net.Dst().String(),
		SrcPort:             utils.DecodePort(h.parent.transport.Src().Raw()),
		DstPort:             utils.DecodePort(h.parent.transport.Dst().Raw()),
		Host:                host,
	})

	return nil
}

func smtpDebug(args ...interface{}) {
	smtpLog.Println(args...)
}

func (h *smtpReader) readRequest(b *bufio.Reader) error {

	var (
		tp   = textproto.NewReader(b)
		data []string
	)

nextLine:

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		decoderLog.Error("SMTP Request error",
			zap.String("ident", h.parent.ident),
			zap.Error(err),
		)

		return err
	}

	smtpDebug(ansi.Red, h.parent.ident, "readSMTPRequest", line, ansi.Reset)

	cmd, args := getSMTPCommand(line)

	if cmd == smtpDot {

		smtpDebug("collected data", strings.Join(data, "\n"))

		h.parent.Lock()
		h.smtpRequests = append(h.smtpRequests, &types.SMTPRequest{
			Command: smtpDATA,
			Data:    strings.Join(data, "\n"),
		})
		h.parent.Unlock()

		return nil
	}

	if validSMTPCommand(cmd) {

		if cmd == smtpDATA {
			goto nextLine
		}

		h.parent.Lock()
		h.smtpRequests = append(h.smtpRequests, &types.SMTPRequest{
			Command:  cmd,
			Argument: strings.Join(args, " "),
			Data:     strings.Join(data, "\n"),
		})
		h.parent.Unlock()

	} else { // its data
		if line == "" {
			line = "\n"
		}
		data = append(data, line)
		goto nextLine
	}

	if cmd == smtpQUIT {
		return io.EOF
	}

	return nil
}

// cuts the line into command and arguments.
func getSMTPCommand(line string) (string, []string) {
	line = strings.Trim(line, "\r \n")
	cmd := strings.Split(line, " ")

	if strings.ToUpper(cmd[0]) == "MAIL" || strings.ToUpper(cmd[0]) == "RCPT" {
		cmd = strings.Split(line, ": ")
		cmd[1] = strings.Trim(cmd[1], "<>")
	}

	return strings.ToUpper(cmd[0]), cmd[1:]
}

func (h *smtpReader) readResponse(b *bufio.Reader) error {

	var (
		tp   = textproto.NewReader(b)
		data []string
		cmd  string
		args []string
	)

nextLine:
	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		logReassemblyError(opSMTPResponse, h.parent.ident, err)

		return err
	}

	smtpDebug(ansi.Blue, h.parent.ident, "readSMTPResponse", line, ansi.Reset)

	cmd, args = getSMTPCommand(line)

	// handle data in response
	if strings.Contains(cmd, "-") {
		// more to come
		data = append(data, line)
		goto nextLine
	}

	code, err := strconv.Atoi(cmd)
	if err != nil {
		smtpDebug(ansi.Red, h.parent.ident, "invalid response code", cmd)
	}

	h.parent.Lock()
	h.smtpResponses = append(h.smtpResponses, &types.SMTPResponse{
		ResponseCode: int32(code),
		Parameter:    strings.Join(args, " "),
		Data:         strings.Join(data, "\n"),
	})
	h.parent.Unlock()

	// if QUIT was acked - quit
	if code == smtpOK && strings.Contains(args[len(args)-1], smtpQUIT) {
		return io.EOF
	}

	return nil
}

// process the SMTP conversation and returns a list of extracted mail identifiers
func (h *smtpReader) parseMails() (mailIDs []string) {
	if len(h.smtpResponses) == 0 || len(h.smtpRequests) == 0 {
		return
	}

	var (
		//state    = stateNotAuthenticated
		numMails int
		from, to string
		next     = func() *types.SMTPRequest {
			return h.smtpRequests[h.reqIndex]
		}
		r *types.SMTPRequest
	)

	// process each request
	for {
		if h.reqIndex == len(h.smtpRequests) {
			return
		}

		// fetch next and increase the index
		r = next()
		h.reqIndex++

		smtpDebug("CMD", r.Command, r.Argument, "h.resIndex", h.resIndex)

		switch r.Command {
		case smtpEHLO, smtpHELO:
			h.resIndex += 2 // skip greeting and helo confirmation replies

			continue
		case smtpDATA:

			mail := h.parseMail([]byte(r.Data), from, to)
			writeMail(mail)
			mailIDs = append(mailIDs, mail.ID)
			numMails++
			h.resIndex++

			continue

		case smtpMAILFROM:
			if len(h.smtpResponses) <= h.resIndex {
				continue
			}

			reply := h.smtpResponses[h.resIndex]
			if reply.ResponseCode == smtpMailActionCompleted {
				from = r.Argument
			}

			h.resIndex++

			continue
		case smtpRCPTTO:

			if len(h.smtpResponses) <= h.resIndex {
				continue
			}

			reply := h.smtpResponses[h.resIndex]

			if reply.ResponseCode == smtpMailActionCompleted {
				to = r.Argument
			}

			h.resIndex++

			continue
		case "QUIT":
			return
		default:
			smtpDebug("unhandled SMTP command: ", r.Command)
			h.resIndex++
		}
	}
}

// TODO: reuse func from POP3 implementation?
func (h *smtpReader) parseMail(buf []byte, from, to string) *types.Mail {

	smtpDebug(ansi.Yellow, "parseMail, from:", from, "to:", to, h.parent.ident, "\n", string(buf), ansi.Reset)

	var (
		hdr, body = splitMailHeaderAndBody(buf)
		ti int64
	)

	ts, err := dateparse.ParseAny(hdr["Delivery-Date"])
	if err != nil {
		decoderLog.Error("failed to parse delivery date string from mail header", zap.Error(err))
	} else {
		ti = ts.UnixNano()
	}

	mail := &types.Mail{
		ReturnPath:   hdr["Return-Path"],
		Timestamp:    ti,
		DeliveryDate: hdr["Delivery-Date"],
		// using the values from the SMTP commands instead of the value on the actual mail header
		From:            from, // header["From"],
		To:              to,   // header["To"],
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
		Body:            h.parseParts(body),
		ID:              newMailID(),
		Origin:          "SMTP",
	}
	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true

			if conf.FileStorage != "" {
				err = h.saveFile("SMTP", p.Filename, nil, []byte(p.Content), []string{p.Header["Content-Transfer-Encoding"]}, h.parent.server.ServiceIdent())
				if err != nil {
					decoderLog.Error("failed to save SMTP attachment", zap.Error(err))
					smtpDebug("failed to save SMTP attachment", err)
				}
			}

			break
		}
	}

	return mail
}

// TODO: reuse func from POP3 implementation
func (h *smtpReader) parseParts(body string) []*types.MailPart {
	var (
		parts        []*types.MailPart
		currentPart  *types.MailPart
		parsePayload bool
		tr           = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	smtpDebug(ansi.White, "parseParts", h.parent.ident, "body:", body, ansi.Reset)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else {
				smtpDebug(ansi.Yellow, h.parent.ident, "failed to read line: "+err.Error())

				return parts
			}
		}

		smtpDebug(ansi.Green, h.parent.ident, "readLine", line)

		if currentPart != nil {
			if parsePayload {
				// check if its an end marker for the current part
				if strings.HasSuffix(line, currentPart.ID+"--") {
					smtpDebug(ansi.Cyan, "end", currentPart.ID, ansi.Reset)
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
					smtpDebug(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// second type of start marker
				} else if strings.HasPrefix(line, "--") && len(line) > 25 && !strings.Contains(line, ">") {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:     strings.TrimPrefix(line, "--"),
						Header: make(map[string]string),
					}
					parsePayload = false
					smtpDebug(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// its content
				} else {
					currentPart.Content += line + "\n"
					smtpDebug(ansi.Blue, "adding content", line, ansi.Reset)
				}
				continue
			}
			pts := strings.Split(line, ": ")
			if len(pts) == 2 {
				currentPart.Header[pts[0]] = pts[1]
				smtpDebug(ansi.Yellow, h.parent.ident, "parsed header field: "+pts[0], ansi.Reset)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					smtpDebug(ansi.Yellow, h.parent.ident, "parsed filename field: "+currentPart.Filename, ansi.Reset)
				}
			}

			if line == "\n" || line == "" {
				parsePayload = true
				smtpDebug(ansi.Green, "start parsing payload", ansi.Reset)
			}

			continue
		}
		// start marker type 1
		if strings.HasPrefix(line, partIdent) {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, partIdent),
				Header: make(map[string]string),
			}
			smtpDebug(ansi.Red, h.parent.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, "--"),
				Header: make(map[string]string),
			}
			smtpDebug(ansi.Red, h.parent.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}

		// single parts have no markers
		smtpDebug(ansi.Red, "no marker found", line, ansi.Reset)

		currentPart = &types.MailPart{
			ID:     "none",
			Header: make(map[string]string),
		}
		pts := strings.Split(line, ": ")

		if len(pts) == 2 {
			currentPart.Header[pts[0]] = pts[1]
			smtpDebug(ansi.Yellow, h.parent.ident, "parsed header field: "+pts[0])
		} else {
			pts = strings.Split(line, "filename=")
			if len(pts) == 2 {
				currentPart.Filename = strings.Trim(pts[1], "\"")
				smtpDebug(ansi.Yellow, "parsed filename field", currentPart.Filename, ansi.Reset)
			}
		}
		if line == "\n" || line == "" {
			parsePayload = true
			smtpDebug(ansi.Green, "start parsing payload", ansi.Reset)
		}
	}

	return parts
}
