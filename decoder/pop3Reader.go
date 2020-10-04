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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/araddon/dateparse"
	"github.com/dreadl0ck/cryptoutils"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

/*
 * POP3 protocol
 */

// pop3State describes a state in the POP3 state machine.
type pop3State int

const (
	stateNotAuthenticated pop3State = iota
	stateAuthenticated
	// StateNotIdentified
	// StateDataTransfer.
)

const (
	// POP3 commands.
	pop3OK             = "+OK"
	pop3Err            = "-ERR"
	pop3Dot            = "."
	pop3Plus           = "+"
	pop3Implementation = "IMPLEMENTATION"
	pop3Top            = "TOP"
	pop3User           = "USER"
	pop3UIDL           = "UIDL"
	pop3STLS           = "STLS"
	pop3SASL           = "SASL"

	// POP3 logging constants.
	opPop3Save = "POP3-save"
)

type pop3Reader struct {
	parent *tcpConnection

	pop3Requests  []*types.POP3Request
	pop3Responses []*types.POP3Response
	reqIndex      int
	resIndex      int

	user, pass, token string
}

func validPop3ServerCommand(cmd string) bool {
	switch cmd {
	case pop3Dot, pop3Plus, pop3OK, pop3Err, pop3Top, pop3User, pop3UIDL, pop3STLS, pop3SASL, pop3Implementation:
		return true
	default:
		return false
	}
}

// Decode parses the stream according to the POP3 protocol.
func (h *pop3Reader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if pop3Decoder.writer == nil {
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

	// fmt.Println(servicePOP3, h.parent.ident, len(h.pop3Responses), len(h.pop3Requests))

	mails, user, pass, token := h.parseMails()
	pop3Msg := &types.POP3{
		Timestamp: h.parent.firstPacket.UnixNano(),
		ClientIP:  h.parent.net.Src().String(),
		ServerIP:  h.parent.net.Dst().String(),
		AuthToken: token,
		User:      user,
		Pass:      pass,
		MailIDs:   mails,
	}

	if user != "" || pass != "" {
		writeCredentials(&types.Credentials{
			Timestamp: h.parent.firstPacket.UnixNano(),
			Service:   servicePOP3,
			Flow:      h.parent.ident,
			User:      user,
			Password:  pass,
		})
	}

	// export metrics if configured
	if conf.ExportMetrics {
		pop3Msg.Inc()
	}

	// write record to disk
	atomic.AddInt64(&pop3Decoder.numRecords, 1)

	err := pop3Decoder.writer.Write(pop3Msg)
	if err != nil {
		errorMap.Inc(err.Error())
	}
}

func (h *pop3Reader) saveFile(source, name string, err error, body []byte, encoding []string, host string) error {

	decoderLog.Info("pop3Reader.saveFile",
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
		logReassemblyError("POP3-create", fmt.Sprintf("cannot create %s", target), err)

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
			logReassemblyError("POP3-gunzip", "Failed to gzip decode: %s", err)
		}
	}

	// Decode base64
	if len(encoding) > 0 && (encoding[0] == "base64") {
		r, _ = base64.NewDecoder(base64.StdEncoding, r).(io.Reader)
	}

	if err == nil {
		w, errCopy := io.Copy(f, r)
		if errCopy != nil {
			logReassemblyError(opPop3Save, fmt.Sprintf("%s: failed to save %s (l:%d)", h.parent.ident, target, w), errCopy)
		} else {
			reassemblyLog.Debug("saved POP3 data",
				zap.String("ident", h.parent.ident),
				zap.String("target", target),
				zap.Int64("written", w),
			)
		}

		if _, ok := r.(*gzip.Reader); ok {
			errClose := r.(*gzip.Reader).Close()
			if errClose != nil {
				logReassemblyError(opPop3Save, fmt.Sprintf("%s: failed to close gzip reader %s (l:%d)", h.parent.ident, target, w), errClose)
			}
		}

		errClose := f.Close()
		if errClose != nil {
			logReassemblyError(opPop3Save, fmt.Sprintf("%s: failed to close file handle %s (l:%d)", h.parent.ident, target, w), errClose)
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

func pop3Debug(args ...interface{}) {
	pop3Log.Println(args...)
}

func (h *pop3Reader) readRequest(b *bufio.Reader) error {
	tp := textproto.NewReader(b)

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		decoderLog.Error("POP3 Request error",
			zap.String("ident", h.parent.ident),
			zap.Error(err),
		)

		return err
	}

	pop3Debug(ansi.Red, h.parent.ident, "readRequest", line, ansi.Reset)

	cmd, args := getCommand(line)

	h.parent.Lock()
	h.pop3Requests = append(h.pop3Requests, &types.POP3Request{
		Command:  cmd,
		Argument: strings.Join(args, " "),
	})
	h.parent.Unlock()

	if cmd == "QUIT" {
		return io.EOF
	}

	return nil
}

func (h *pop3Reader) readResponse(b *bufio.Reader) error {
	tp := textproto.NewReader(b)

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		logReassemblyError("POP3-response", h.parent.ident, err)

		return err
	}

	pop3Debug(ansi.Blue, h.parent.ident, "readResponse", line, ansi.Reset)

	cmd, args := getCommand(line)

	if validPop3ServerCommand(cmd) {
		h.parent.Lock()
		h.pop3Responses = append(h.pop3Responses, &types.POP3Response{
			Command: cmd,
			Message: strings.Join(args, " "),
		})
		h.parent.Unlock()
	} else {
		if line == "" {
			line = "\n"
		}
		h.parent.Lock()
		h.pop3Responses = append(h.pop3Responses, &types.POP3Response{
			Message: line,
		})
		h.parent.Unlock()
	}

	if line == "-ERR authentication failed" || strings.Contains(line, "signing off") {
		return io.EOF
	}

	return nil
}

// cuts the line into command and arguments.
func getCommand(line string) (string, []string) {
	line = strings.Trim(line, "\r \n")
	cmd := strings.Split(line, " ")

	return cmd[0], cmd[1:]
}

func (h *pop3Reader) parseMails() (mailIDs []string, user, pass, token string) {
	if len(h.pop3Responses) == 0 || len(h.pop3Requests) == 0 {
		return
	}

	// check if server hello
	serverHello := h.pop3Responses[0]
	if serverHello.Command != pop3OK {
		return
	}

	if !strings.HasPrefix(serverHello.Message, "POP server ready") {
		return
	}

	var (
		state    = stateNotAuthenticated
		numMails int
		next     = func() *types.POP3Request {
			return h.pop3Requests[h.reqIndex]
		}
		mailBuf string
		r       *types.POP3Request
	)

	for {
		if h.reqIndex == len(h.pop3Requests) {
			return
		}

		r = next()
		h.reqIndex++
		// fmt.Println("CMD", r.Command, r.Argument, "h.resIndex", h.resIndex)

		switch state {
		case stateAuthenticated:
			switch r.Command {
			case "STAT":
				h.resIndex++

				continue
			case "LIST", pop3UIDL:
				var n int
				// ensure safe array access
				if len(h.pop3Responses) < h.resIndex {
					continue
				}

				for _, reply := range h.pop3Responses[h.resIndex:] {
					if reply.Command == pop3Dot {
						numMails++
						h.resIndex++

						break
					}
					n++
				}

				h.resIndex += n

				continue
			case "RETR":
				var n int
				// ensure safe array access
				if len(h.pop3Responses) < h.resIndex {
					continue
				}

				for _, reply := range h.pop3Responses[h.resIndex:] {
					if reply.Command == pop3Dot {
						mail := h.parseMail([]byte(mailBuf))
						writeMail(mail)
						mailIDs = append(mailIDs, mail.ID)
						mailBuf = ""
						numMails++
						h.resIndex++

						break
					}

					mailBuf += reply.Message + "\n"
					n++
				}

				h.resIndex += n

				continue
			case "QUIT":
				return
			}
		case stateNotAuthenticated:
			switch r.Command {
			case pop3User:
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					user = r.Argument
				}

				h.resIndex++

				continue
			case "CAPA":
				var n int

				for _, reply := range h.pop3Responses[h.resIndex:] {
					if reply.Command == pop3Dot {
						numMails++
						h.resIndex++

						break
					}
					n++
				}

				h.resIndex += n

				continue
			case "AUTH":
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					state = stateAuthenticated

					if len(h.pop3Requests) >= h.reqIndex {
						r = h.pop3Requests[h.reqIndex]
						if r != nil {
							token = r.Command
						}
					}
				}

				h.resIndex++

				continue
			case "PASS":
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					state = stateAuthenticated
					pass = r.Argument
				}

				h.resIndex++

				continue
			case "APOP": // example: APOP mrose c4c9334bac560ecc979e58001b3e22fb
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					state = stateAuthenticated
					parts := strings.Split(r.Argument, " ")

					if len(parts) > 1 {
						user = parts[0]
						token = parts[1]
					}
				}

				h.resIndex++

				continue
			case "QUIT":
				return
			case "STAT":
				h.resIndex++

				continue
			default:
				pop3Debug("unhandled POP3 command: ", r.Command)
				h.resIndex++
			}
		}
		h.resIndex++
	}
}

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

func (h *pop3Reader) parseMail(buf []byte) *types.Mail {
	pop3Debug(ansi.Yellow, "parseMail", h.parent.ident, ansi.Reset)

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
		ReturnPath:      hdr["Return-Path"],
		Timestamp:       ti,
		DeliveryDate:    hdr["Delivery-Date"],
		From:            hdr["From"],
		To:              hdr["To"],
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
		Origin:          "POP3",
	}
	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true

			if conf.FileStorage != "" {
				err = h.saveFile("POP3", p.Filename, nil, []byte(p.Content), []string{p.Header["Content-Transfer-Encoding"]}, h.parent.server.ServiceIdent())
				if err != nil {
					decoderLog.Error("failed to save POP3 attachment", zap.Error(err))
				}
			}

			break
		}
	}

	return mail
}

const partIdent = "------=_Part_"

func (h *pop3Reader) parseParts(body string) []*types.MailPart {
	var (
		parts        []*types.MailPart
		currentPart  *types.MailPart
		parsePayload bool
		tr           = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	pop3Debug(ansi.White, h.parent.ident, "body:", body, ansi.Reset)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else {
				pop3Debug(ansi.Yellow, h.parent.ident, "failed to read line: "+err.Error())

				return parts
			}
		}

		pop3Debug(ansi.Green, h.parent.ident, "readLine", line)

		if currentPart != nil {
			if parsePayload {
				// check if its an end marker for the current part
				if strings.HasSuffix(line, currentPart.ID+"--") {
					pop3Debug(ansi.Cyan, "end", currentPart.ID, ansi.Reset)
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
					pop3Debug(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// second type of start marker
				} else if strings.HasPrefix(line, "--") && len(line) > 25 && !strings.Contains(line, ">") {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:     strings.TrimPrefix(line, "--"),
						Header: make(map[string]string),
					}
					parsePayload = false
					pop3Debug(ansi.Red, "start", currentPart.ID, ansi.Reset)

					// its content
				} else {
					currentPart.Content += line + "\n"
					pop3Debug(ansi.Blue, "adding content", line, ansi.Reset)
				}
				continue
			}
			pts := strings.Split(line, ": ")
			if len(pts) == 2 {
				currentPart.Header[pts[0]] = pts[1]
				pop3Debug(ansi.Yellow, h.parent.ident, "parsed header field: "+pts[0], ansi.Reset)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					pop3Debug(ansi.Yellow, h.parent.ident, "parsed filename field: "+currentPart.Filename, ansi.Reset)
				}
			}

			if line == "\n" || line == "" {
				parsePayload = true
				pop3Debug(ansi.Green, "start parsing payload", ansi.Reset)
			}

			continue
		}
		// start marker type 1
		if strings.HasPrefix(line, partIdent) {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, partIdent),
				Header: make(map[string]string),
			}
			pop3Debug(ansi.Red, h.parent.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:     strings.TrimPrefix(line, "--"),
				Header: make(map[string]string),
			}
			pop3Debug(ansi.Red, h.parent.ident, "start: "+currentPart.ID, ansi.Reset)

			continue
		}

		// single parts have no markers
		pop3Debug(ansi.Red, "no marker found", line, ansi.Reset)

		currentPart = &types.MailPart{
			ID:     "none",
			Header: make(map[string]string),
		}
		pts := strings.Split(line, ": ")

		if len(pts) == 2 {
			currentPart.Header[pts[0]] = pts[1]
			pop3Debug(ansi.Yellow, h.parent.ident, "parsed header field: "+pts[0])
		} else {
			pts = strings.Split(line, "filename=")
			if len(pts) == 2 {
				currentPart.Filename = strings.Trim(pts[1], "\"")
				pop3Debug(ansi.Yellow, "parsed filename field", currentPart.Filename, ansi.Reset)
			}
		}
		if line == "\n" || line == "" {
			parsePayload = true
			pop3Debug(ansi.Green, "start parsing payload", ansi.Reset)
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

func newMailID() string {
	s, err := cryptoutils.RandomString(20)
	if err != nil {
		log.Fatal(err)
	}

	return s
}

// TODO: write unit test for this
//< +OK POP3 server ready <mailserver.mydomain.com>
//>USER user1
//< +OK
//>PASS <password>
//<+OK user1's maildrop has 2 messages (320 octets)
//> STAT
//< +OK 2 320
//> LIST
//< +OK 2 messages

// save token
// request: AUTH PLAIN
// next command is token

// parse user and MD5 from APOP cmd
// S: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
// C: APOP mrose c4c9334bac560ecc979e58001b3e22fb
// S: +OK maildrop has 1 message (369 octets)

// save USER name and PASS
//Possible Responses:
//+OK name is a valid mailbox
//-ERR never heard of mailbox name
//
//Examples:
//C: USER frated
//S: -ERR sorry, no mailbox for frated here
//...
//C: USER mrose
//S: +OK mrose is a real hoopy frood

// test wrong and corrrect PASS cmd usage
//Possible Responses:
//+OK maildrop locked and ready
//-ERR invalid password
//-ERR unable to lock maildrop
//
//Examples:
//C: USER mrose
//S: +OK mrose is a real hoopy frood
//C: PASS secret
//S: -ERR maildrop already locked
//...
//C: USER mrose
//S: +OK mrose is a real hoopy frood
//C: PASS secret
//S: +OK mrose's maildrop has 2 messages (320 octets)
