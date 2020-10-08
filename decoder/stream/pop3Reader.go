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
	"errors"
	"github.com/dreadl0ck/netcap/decoder/utils"
	"io"
	"log"
	"net/textproto"
	"strings"
	"sync/atomic"

	"github.com/dreadl0ck/cryptoutils"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/types"
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
	conversation *conversationInfo

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

func (h *pop3Reader) New(conv *conversationInfo) streamDecoder {
	return &pop3Reader{
		conversation: conv,
	}
}

// Decode parses the stream according to the POP3 protocol.
func (h *pop3Reader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if pop3Decoder.writer == nil {
		return
	}

	decodeConversation(
		h.conversation.ident,
		h.conversation.data,
		func(b *bufio.Reader) error {
			return h.readRequest(b)
		},
		func(b *bufio.Reader) error {
			return h.readResponse(b)
		},
	)

	// fmt.Println(servicePOP3, h.parent.ident, len(h.pop3Responses), len(h.pop3Requests))

	var commands []string
	for _, c := range h.pop3Requests {
		commands = append(commands, c.Command)
	}

	mails, user, pass, token := h.processPOP3Conversation()
	pop3Msg := &types.POP3{
		Timestamp: h.conversation.firstClientPacket.UnixNano(),
		ClientIP:  h.conversation.clientIP,
		ServerIP:  h.conversation.serverIP,
		AuthToken: token,
		User:      user,
		Pass:      pass,
		MailIDs:   mails,
		Commands:  commands,
	}

	if user != "" || pass != "" {
		writeCredentials(&types.Credentials{
			Timestamp: h.conversation.firstClientPacket.UnixNano(),
			Service:   servicePOP3,
			Flow:      h.conversation.ident,
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
		utils.ErrorMap.Inc(err.Error())
	}
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
		streamLog.Error("POP3 Request error",
			zap.String("ident", h.conversation.ident),
			zap.Error(err),
		)

		return err
	}

	pop3Debug(ansi.Red, h.conversation.ident, "readRequest", line, ansi.Reset)

	cmd, args := getCommand(line)

	h.pop3Requests = append(h.pop3Requests, &types.POP3Request{
		Command:  cmd,
		Argument: strings.Join(args, " "),
	})

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
		logReassemblyError("POP3-response", h.conversation.ident, err)

		return err
	}

	pop3Debug(ansi.Blue, h.conversation.ident, "readResponse", line, ansi.Reset)

	cmd, args := getCommand(line)

	if validPop3ServerCommand(cmd) {
		h.pop3Responses = append(h.pop3Responses, &types.POP3Response{
			Command: cmd,
			Message: strings.Join(args, " "),
		})
	} else {
		if line == "" {
			line = "\n"
		}
		h.pop3Responses = append(h.pop3Responses, &types.POP3Response{
			Message: line,
		})
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

func (h *pop3Reader) processPOP3Conversation() (mailIDs []string, user, pass, token string) {
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
						mail := parseMail(h.conversation, []byte(mailBuf), "", "", pop3Log, servicePOP3)
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
