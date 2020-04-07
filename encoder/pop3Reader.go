/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
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
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/dreadl0ck/cryptoutils"
	"github.com/mgutz/ansi"

	gzip "github.com/klauspost/pgzip"

	"github.com/dreadl0ck/netcap/types"
)

/*
 * POP3 part
 */

const pop3Debug = false

type pop3Reader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpStream

	reqIndex int
	resIndex int

	user, pass, token string
}

func (h *pop3Reader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		select {
		case h.data, ok = <-h.bytes:
		// time out streams that never send any data
		// for HTTP this is not done currently, because it caused the assembler to lock up for some datasets
		// TODO: test empty TCP conn over HTTP port (will this lock up the reassembly?)
		case <-time.After(timeout):
			return 0, io.EOF
		}
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *pop3Reader) BytesChan() chan []byte {
	return h.bytes
}

func (h *pop3Reader) Cleanup(wg *sync.WaitGroup, s2c Connection, c2s Connection) {

	// fmt.Println("POP3 cleanup", h.ident)

	// determine if one side of the stream has already been closed
	h.parent.Lock()
	if !h.parent.last {

		// signal wait group
		wg.Done()

		// indicate close on the parent tcpStream
		h.parent.last = true

		// free lock
		h.parent.Unlock()

		return
	}
	h.parent.Unlock()

	// cleanup() is called twice - once for each direction of the stream
	// this check ensures the audit record collection is executed only if one side has been closed already
	// to ensure all necessary requests and responses are present
	if h.parent.last {
		mails, user, pass, token := h.parseMails()
		pop3Msg := &types.POP3{
			Timestamp: h.parent.firstPacket.String(),
			ClientIP:    h.parent.net.Src().String(),
			ServerIP:    h.parent.net.Dst().String(),
			AuthToken: token,
			User:      user,
			Pass:      pass,
			Mails: mails,
		}

		// export metrics if configured
		if pop3Encoder.export {
			pop3Msg.Inc()
		}

		// write record to disk
		atomic.AddInt64(&pop3Encoder.numRecords, 1)
		err := pop3Encoder.writer.Write(pop3Msg)
		if err != nil {
			errorMap.Inc(err.Error())
		}

		// inserts a newline to increase readability
		mailDebug()
	}

	// signal wait group
	wg.Done()
}

// run starts decoding POP3 traffic in a single direction
func (h *pop3Reader) Run(wg *sync.WaitGroup) {

	// create streams
	var (
		// client to server
		c2s = Connection{h.parent.net, h.parent.transport}
		// server to client
		s2c = Connection{h.parent.net.Reverse(), h.parent.transport.Reverse()}
	)

	// defer a cleanup func to flush the requests and responses once the stream encounters an EOF
	defer h.Cleanup(wg, s2c, c2s)

	var (
		err error
		b   = bufio.NewReader(h)
	)
	for {
		// handle parsing POP3 requests
		if h.isClient {
			err = h.readRequest(b, c2s)
		} else {
			// handle parsing POP3 responses
			err = h.readResponse(b, s2c)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// stop in case of EOF
			break
		} else {
			// continue on all other errors
			continue
		}
	}
}

func (h *pop3Reader) saveFile(source, name string, err error, body []byte, encoding []string) error {

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
		ctype = http.DetectContentType(body)

		// root path
		root = path.Join(FileStorage, ctype)

		// file extension
		ext = fileExtensionForContentType(ctype)

		// file basename
		base = filepath.Clean(name+"-"+path.Base(h.ident)) + ext
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
	os.MkdirAll(root, 0755)
	base = path.Join(root, base)
	if len(base) > 250 {
		base = base[:250] + "..."
	}
	if base == FileStorage {
		base = path.Join(FileStorage, "noname")
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
			target = path.Join(root, filepath.Clean("incomplete-"+name+"-"+h.ident)+"-"+strconv.Itoa(n)+fileExtensionForContentType(ctype))
		} else {
			target = path.Join(root, filepath.Clean(name+"-"+h.ident)+"-"+strconv.Itoa(n)+fileExtensionForContentType(ctype))
		}

		n++
	}

	//fmt.Println("saving file:", target)

	f, err := os.Create(target)
	if err != nil {
		logError("POP3-create", "Cannot create %s: %s\n", target, err)
		return err
	}

	// explicitly declare io.Reader interface
	var r io.Reader

	// now assign a new buffer
	r = bytes.NewBuffer(body)
	if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
		r, err = gzip.NewReader(r)
		if err != nil {
			logError("POP3-gunzip", "Failed to gzip decode: %s", err)
		}
	}
	if err == nil {
		w, err := io.Copy(f, r)
		if _, ok := r.(*gzip.Reader); ok {
			r.(*gzip.Reader).Close()
		}
		f.Close()
		if err != nil {
			logError("POP3-save", "%s: failed to save %s (l:%d): %s\n", h.ident, target, w, err)
		} else {
			logInfo("%s: Saved %s (l:%d)\n", h.ident, target, w)
		}
	}

	// write file to disk
	writeFile(&types.File{
		Timestamp:   h.parent.firstPacket.String(),
		Name:        fileName,
		Length:      int64(len(body)),
		Hash:        hex.EncodeToString(cryptoutils.MD5Data(body)),
		Location:    target,
		Ident:       h.ident,
		Source:      source,
		ContentType: ctype,
		Context: &types.PacketContext{
			SrcIP:   h.parent.net.Src().String(),
			DstIP:   h.parent.net.Dst().String(),
			SrcPort: h.parent.transport.Src().String(),
			DstPort: h.parent.transport.Dst().String(),
		},
	})

	return nil
}

func mailDebug(args ...interface{}) {
	if pop3Debug {
		fmt.Println(args...)
	}
}

func (h *pop3Reader) readRequest(b *bufio.Reader, c2s Connection) error {

	tp := textproto.NewReader(b)

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		fmt.Println("POP3-request", "POP3/%s Request error: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	mailDebug(ansi.Red, h.ident, "readRequest", line, ansi.Reset)

	cmd, args := getCommand(line)

	h.parent.Lock()
	h.parent.pop3Requests = append(h.parent.pop3Requests, &types.POP3Request{
		Command:  cmd,
		Argument: strings.Join(args, " "),
	})
	h.parent.Unlock()

	if cmd == "QUIT" {
		return io.EOF
	}

	return nil
}

func (h *pop3Reader) readResponse(b *bufio.Reader, s2c Connection) error {

	tp := textproto.NewReader(b)

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return err
	} else if err != nil {
		fmt.Println("POP3-response", "POP3/%s Response error: %s (%v,%+v)\n", h.ident, err, err, err)
		return err
	}

	mailDebug(ansi.Blue, h.ident, "readResponse", line, ansi.Reset)

	cmd, args := getCommand(line)

	if validPop3ServerCommand(cmd) {
		h.parent.Lock()
		h.parent.pop3Responses = append(h.parent.pop3Responses, &types.POP3Response{
			Command: cmd,
			Message: strings.Join(args, " "),
		})
		h.parent.Unlock()
	} else {
		if line == "" {
			line = "\n"
		}
		h.parent.Lock()
		h.parent.pop3Responses = append(h.parent.pop3Responses, &types.POP3Response{
			Message: line,
		})
		h.parent.Unlock()
	}

	if line == "-ERR authentication failed" || strings.Contains(line, "signing off") {
		return io.EOF
	}

	return nil
}

// cuts the line into command and arguments
func getCommand(line string) (string, []string) {
	line = strings.Trim(line, "\r \n")
	cmd := strings.Split(line, " ")
	return cmd[0], cmd[1:]
}

func validPop3ServerCommand(cmd string) bool {
	switch cmd {
	case ".":
		fallthrough
	case "+":
		fallthrough
	case "+OK":
		fallthrough
	case "-ERR":
		fallthrough
	case "TOP":
		fallthrough
	case "USER":
		fallthrough
	case "UIDL":
		fallthrough
	case "STLS":
		fallthrough
	case "SASL":
		fallthrough
	case "IMPLEMENTATION":
		return true
	default:
		return false
	}
}

type POP3State int

const (
	StateNotAuthenticated POP3State = iota
	StateNotIdentified
	StateAuthenticated
	StateDataTransfer
)

func (h *pop3Reader) parseMails() (mails []*types.Mail, user, pass, token string) {

	if len(h.parent.pop3Responses) == 0 || len(h.parent.pop3Requests) == 0 {
		return
	}

	// check if server hello
	serverHello := h.parent.pop3Responses[0]
	if serverHello.Command != "+OK" {
		return
	}
	if !strings.HasPrefix(serverHello.Message, "POP server ready") {
		return
	}

	var (
		state    POP3State = StateNotAuthenticated
		numMails int
		next     = func() *types.POP3Request {
			return h.parent.pop3Requests[h.reqIndex]
		}
		mailBuf string
	)

	for {
		if h.reqIndex == len(h.parent.pop3Requests) {
			return
		}
		r := next()
		h.reqIndex++
		//fmt.Println("CMD", r.Command, r.Argument, "h.resIndex", h.resIndex)

		switch state {
		case StateAuthenticated:
			switch r.Command {
			case "STAT":
				h.resIndex++
				continue
			case "LIST", "UIDL":
				var n int
				for _, reply := range h.parent.pop3Responses[h.resIndex:] {
					if reply.Command == "." {
						numMails++
						h.resIndex++
						break
					}
					n++
				}
				h.resIndex = h.resIndex + n
				continue
			case "RETR":
				var n int
				for _, reply := range h.parent.pop3Responses[h.resIndex:] {
					if reply.Command == "." {
						mails = append(mails, parseMail([]byte(mailBuf)))
						mailBuf = ""
						numMails++
						h.resIndex++
						break
					}
					mailBuf += reply.Message + "\n"
					n++
				}
				h.resIndex = h.resIndex + n
				continue
			case "QUIT":
				return
			}
		case StateNotAuthenticated:
			switch r.Command {
			case "USER":
				reply := h.parent.pop3Responses[h.resIndex+1]
				if reply.Command == "+OK" {
					user = r.Argument
				}
				h.resIndex++
				continue
			case "CAPA":
				var n int
				for _, reply := range h.parent.pop3Responses[h.resIndex:] {
					if reply.Command == "." {
						numMails++
						h.resIndex++
						break
					}
					n++
				}
				h.resIndex = h.resIndex + n
				continue
			case "AUTH":
				reply := h.parent.pop3Responses[h.resIndex+1]
				if reply.Command == "+OK" {
					state = StateAuthenticated
					r := h.parent.pop3Requests[h.reqIndex]
					if r != nil {
						token = r.Command
					}
				}
				h.resIndex++
				continue
			case "PASS":
				reply := h.parent.pop3Responses[h.resIndex+1]
				if reply.Command == "+OK" {
					state = StateAuthenticated
					pass = r.Argument
				}
				h.resIndex++
				continue
			case "APOP": // example: APOP mrose c4c9334bac560ecc979e58001b3e22fb
				reply := h.parent.pop3Responses[h.resIndex+1]
				if reply.Command == "+OK" {
					state = StateAuthenticated
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
			continue
		}

		parts := strings.Split(line, ": ")
		if len(parts) == 0 {
			header[lastHeader] += "\n" + line
			continue
		}

		// should be an uppercase char if header field
		// multi line values start with a whitespace
		if unicode.IsUpper(rune(parts[0][0])) {
			if parts[0] == "Envelope-To" {
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

func parseMail(buf []byte) *types.Mail {
	header, body := splitMailHeaderAndBody(buf)
	mail := &types.Mail{
		ReturnPath:      header["Return-Path"],
		DeliveryDate:    header["Delivery-Date"],
		From:            header["From"],
		To:              header["To"],
		CC:              header["CC"],
		Subject:         header["Subject"],
		Date:            header["Date"],
		MessageID:       header["Message-ID"],
		References:      header["References"],
		InReplyTo:       header["In-Reply-To"],
		ContentLanguage: header["Content-Language"],
		XOriginatingIP: header["x-originating-ip"],
		ContentType:    header["Content-Type"],
		EnvelopeTo:     header["Envelope-To"],
		Body:           parseParts(body),
	}
	for _, p := range mail.Body {
		if strings.Contains(p.Header["Content-Disposition"], "attachment") {
			mail.HasAttachments = true
			break
		}
	}
	return mail
}

const partIdent = "------=_Part_"

func parseParts(body string) []*types.MailPart {

	var (
		parts []*types.MailPart
		currentPart *types.MailPart
		parsePayload bool
		tr = textproto.NewReader(bufio.NewReader(bytes.NewReader([]byte(body))))
	)

	for {
		line, err := tr.ReadLine()
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			} else {
				fmt.Println(err)
				return parts
			}
		}

		mailDebug("readLine", line)

		if currentPart != nil {
			if parsePayload {
				// check if its an end marker for the current part
				if strings.HasSuffix(line, currentPart.ID + "--") {
					mailDebug(ansi.Cyan, "end", currentPart.ID, ansi.Reset)
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
					mailDebug(ansi.Red, "start", currentPart.ID, ansi.Reset)

				// second type of start marker
				} else if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
					parts = append(parts, copyMailPart(currentPart))
					currentPart = &types.MailPart{
						ID:      strings.TrimPrefix(line, "--"),
						Header:  make(map[string]string),
					}
					parsePayload = false
					mailDebug(ansi.Red, "start", currentPart.ID, ansi.Reset)

				// its content
				} else {
					currentPart.Content += line + "\n"
					mailDebug(ansi.Blue, "adding content", line, ansi.Reset)
				}
				continue
			}
			pts := strings.Split(line, ": ")
			if len(pts) == 2 {
				currentPart.Header[pts[0]] = pts[1]
				mailDebug(ansi.Yellow, "parsed header field", pts[0], ansi.Reset)
			} else {
				pts = strings.Split(line, "filename=")
				if len(pts) == 2 {
					currentPart.Filename = strings.Trim(pts[1], "\"")
					mailDebug(ansi.Yellow, "parsed filename field", currentPart.Filename, ansi.Reset)
				}
			}
			if line == "\n" || line == "" {
				parsePayload = true
				mailDebug(ansi.Green, "start parsing payload", ansi.Reset)
			}
		}
		// start marker type 1
		if strings.HasPrefix(line, partIdent) {
			currentPart = &types.MailPart{
				ID:      strings.TrimPrefix(line, partIdent),
				Header:  make(map[string]string),
			}
			mailDebug(ansi.Red, "start", currentPart.ID, ansi.Reset)
		}
		// start marker type 2
		if strings.HasPrefix(line, "--") && len(line) > 31 && !strings.Contains(line, ">") {
			currentPart = &types.MailPart{
				ID:      strings.TrimPrefix(line, "--"),
				Header:  make(map[string]string),
			}
			mailDebug(ansi.Red, "start", currentPart.ID, ansi.Reset)
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
//S: +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
//C: APOP mrose c4c9334bac560ecc979e58001b3e22fb
//S: +OK maildrop has 1 message (369 octets)

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
