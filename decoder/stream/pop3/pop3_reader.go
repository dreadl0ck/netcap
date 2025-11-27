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

package pop3

import (
	"bufio"
	"errors"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/decoder/stream/mail"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	"github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
)

// parseMessageID parses a message ID from a string
func parseMessageID(s string) (int32, error) {
	id, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(id), nil
}

// parseMailboxSize parses a mailbox size from a string
func parseMailboxSize(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

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

	pop3STAT = "STAT"
	pop3LIST = "LIST"
	pop3RETR = "RETR"
	pop3QUIT = "QUIT"
	pop3CAPA = "CAPA"
	pop3AUTH = "AUTH"
	pop3PASS = "PASS"
	pop3APOP = "APOP"
)

type pop3Reader struct {
	conversation *core.ConversationInfo

	pop3Requests  []*types.POP3Request
	pop3Responses []*types.POP3Response
	reqIndex      int
	resIndex      int

	user, pass, token string
	
	// Security monitoring fields
	authMethod       string   // USER/PASS, APOP, AUTH PLAIN, etc.
	authSuccess      bool
	authAttempts     int32
	starttlsRequested bool
	starttlsSuccess  bool
	capabilities     []string
	messageCount     int32
	mailboxSize      int64
	retrievedMsgs    []int32
	deletedMsgs      []int32
}

func validPop3ServerCommand(cmd string) bool {
	switch cmd {
	case pop3Dot, pop3Plus, pop3OK, pop3Err, pop3Top, pop3User, pop3UIDL, pop3STLS, pop3SASL, pop3Implementation:
		return true
	default:
		return false
	}
}

// New will instantiate a new POP3 reader.
func (h *pop3Reader) New(conv *core.ConversationInfo) core.StreamDecoderInterface {
	return &pop3Reader{
		conversation: conv,
	}
}

// Decode parses the stream according to the POP3 protocol.
func (h *pop3Reader) Decode() {
	// prevent nil pointer access if decoder is not initialized
	if Decoder.Writer == nil {
		return
	}

	streamutils.DecodeConversation(
		h.conversation.Ident,
		h.conversation.Data,
		func(b *bufio.Reader) error {
			return h.readRequest(b)
		},
		func(b *bufio.Reader) error {
			return h.readResponse(b)
		},
	)

	// fmt.Println(servicePOP3, h.parent.ident, len(h.pop3Responses), len(h.pop3Requests))

	commands := make([]string, 0, len(h.pop3Requests))
	for _, c := range h.pop3Requests {
		commands = append(commands, c.Command)
	}

	mails, user, pass, token := h.processPOP3Conversation()
	
	// Determine if plaintext auth was used (password sent in clear)
	isPlaintextAuth := false
	if h.authMethod == "USER/PASS" && !h.starttlsSuccess && h.conversation.ServerPort != 995 {
		isPlaintextAuth = true
	}
	
	// Determine if connection is encrypted (port 995 = POP3S or STARTTLS success)
	isEncrypted := h.conversation.ServerPort == 995 || h.starttlsSuccess
	
	pop3Msg := &types.POP3{
		Timestamp: h.conversation.FirstClientPacket.UnixNano(),
		ClientIP:  h.conversation.ClientIP,
		ServerIP:  h.conversation.ServerIP,
		AuthToken: token,
		User:      user,
		Pass:      pass,
		MailIDs:   mails,
		Commands:  commands,
		// New port fields
		ClientPort: h.conversation.ClientPort,
		ServerPort: h.conversation.ServerPort,
		// Authentication tracking
		AuthSuccess:        h.authSuccess,
		AuthMethod:         h.authMethod,
		AuthAttempts:       h.authAttempts,
		// Mailbox statistics
		MessageCount:       h.messageCount,
		MailboxSize:        h.mailboxSize,
		// Message operations
		RetrievedMessages:  h.retrievedMsgs,
		DeletedMessages:    h.deletedMsgs,
		// Security monitoring
		STARTTLSRequested:  h.starttlsRequested,
		STARTTLSSuccess:    h.starttlsSuccess,
		IsEncrypted:        isEncrypted,
		IsPlaintextAuth:    isPlaintextAuth,
		ServerCapabilities: h.capabilities,
	}

	if user != "" || pass != "" {
		credentials.WriteCredentials(&types.Credentials{
			Timestamp: h.conversation.FirstClientPacket.UnixNano(),
			Service:   servicePOP3,
			Flow:      h.conversation.Ident,
			User:      user,
			Password:  pass,
		})
	}

	// export metrics if configured
	if decoderconfig.Instance.ExportMetrics {
		pop3Msg.Inc()
	}

	// write record to disk
	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(pop3Msg)
	if err != nil {
		utils.ErrorMap.Inc(err.Error())
	}
}

func pop3Debug(msg string, fields ...zap.Field) {
	pop3Log.Info(msg, fields...)
}

func (h *pop3Reader) readRequest(b *bufio.Reader) error {
	tp := textproto.NewReader(b)

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	} else if err != nil {
		pop3Log.Error("error reading POP3 request",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)

		return err
	}

	pop3Debug("read POP3 request",
		zap.String("ident", h.conversation.Ident),
		zap.String("line", line),
	)

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
		pop3Log.Error("error reading POP3 response",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)

		return err
	}

	pop3Debug("read POP3 response",
		zap.String("ident", h.conversation.Ident),
		zap.String("line", line),
	)

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
		currentMsgID int32 // Track current message being retrieved/deleted
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
			case pop3STAT:
				// Parse STAT response to get message count and mailbox size
				if len(h.pop3Responses) > h.resIndex {
					reply := h.pop3Responses[h.resIndex]
					if reply.Command == pop3OK {
						// Response format: +OK nn mm (nn=message count, mm=mailbox size)
						parts := strings.Fields(reply.Message)
						if len(parts) >= 2 {
							if count, err := parseMessageID(parts[0]); err == nil {
								h.messageCount = count
							}
							if size, err := parseMailboxSize(parts[1]); err == nil {
								h.mailboxSize = size
							}
						}
					}
				}
				h.resIndex++

				continue
			case pop3LIST, pop3UIDL:
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
			case pop3RETR:
				// Track which message is being retrieved
				if msgID, err := parseMessageID(r.Argument); err == nil && msgID > 0 {
					h.retrievedMsgs = append(h.retrievedMsgs, msgID)
					currentMsgID = msgID
				}
				
				var n int
				// ensure safe array access
				if len(h.pop3Responses) < h.resIndex {
					continue
				}

				for _, reply := range h.pop3Responses[h.resIndex:] {
					if reply.Command == pop3Dot {
						m := mail.Parse(h.conversation, []byte(mailBuf), "", "", pop3Log, servicePOP3)
						mail.WriteMail(m)
						mailIDs = append(mailIDs, m.ID)
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
			case "DELE":
				// Track which message is being deleted
				if msgID, err := parseMessageID(r.Argument); err == nil && msgID > 0 {
					h.deletedMsgs = append(h.deletedMsgs, msgID)
				}
				h.resIndex++
				continue
			case pop3QUIT:
				return
			}
			// Suppress unused variable warning
			_ = currentMsgID
		case stateNotAuthenticated:
			switch r.Command {
			case pop3User:
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					user = r.Argument
					h.authMethod = "USER/PASS" // Will be confirmed with PASS
				}

				h.resIndex++

				continue
			case pop3CAPA:
				// Parse CAPA response to extract server capabilities
				var n int
				var capas []string

				for _, reply := range h.pop3Responses[h.resIndex:] {
					if reply.Command == pop3Dot {
						numMails++
						h.resIndex++

						break
					}
					// Each line after +OK is a capability
					if reply.Message != "" && reply.Command != pop3OK {
						capas = append(capas, reply.Message)
					} else if reply.Command == "" && reply.Message != "" {
						capas = append(capas, reply.Message)
					}
					n++
				}
				h.capabilities = capas

				h.resIndex += n

				continue
			case pop3AUTH:
				h.authAttempts++
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					state = stateAuthenticated
					h.authSuccess = true

					// Determine auth method from argument (e.g., AUTH PLAIN, AUTH LOGIN)
					if r.Argument != "" {
						h.authMethod = "AUTH " + strings.ToUpper(r.Argument)
					} else {
						h.authMethod = "AUTH"
					}

					if len(h.pop3Requests) > h.reqIndex {
						r = h.pop3Requests[h.reqIndex]
						if r != nil {
							token = r.Command
						}
					}
				}

				h.resIndex++

				continue
			case pop3PASS:
				h.authAttempts++
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					state = stateAuthenticated
					h.authSuccess = true
					h.authMethod = "USER/PASS"
					pass = r.Argument
				}

				h.resIndex++

				continue
			case pop3APOP: // example: APOP mrose c4c9334bac560ecc979e58001b3e22fb
				h.authAttempts++
				if len(h.pop3Responses) <= h.resIndex+1 {
					continue
				}

				reply := h.pop3Responses[h.resIndex+1]
				if reply.Command == pop3OK {
					state = stateAuthenticated
					h.authSuccess = true
					h.authMethod = "APOP"
					parts := strings.Split(r.Argument, " ")

					if len(parts) > 1 {
						user = parts[0]
						token = parts[1]
					}
				}

				h.resIndex++

				continue
			case pop3STLS:
				// STARTTLS request
				h.starttlsRequested = true
				if len(h.pop3Responses) > h.resIndex {
					reply := h.pop3Responses[h.resIndex]
					if reply.Command == pop3OK {
						h.starttlsSuccess = true
					}
				}
				h.resIndex++

				continue
			case pop3QUIT:
				return
			case pop3STAT:
				h.resIndex++

				continue
			default:
				pop3Debug("unhandled POP3 command",
					zap.String("command", r.Command),
				)
				h.resIndex++
			}
		}
		h.resIndex++
	}
}
