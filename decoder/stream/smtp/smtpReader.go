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

package smtp

import (
	"bufio"
	"errors"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/mail"
	streamutils "github.com/dreadl0ck/netcap/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
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
	conversation *core.ConversationInfo

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

// New returns a SMTP reader instance.
func (h *smtpReader) New(conv *core.ConversationInfo) core.StreamDecoderInterface {
	return &smtpReader{
		conversation: conv,
	}
}

// Decode parses the stream according to the SMTP protocol.
func (h *smtpReader) Decode() {
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

	var commands []string

	for _, c := range h.smtpRequests {
		commands = append(commands, c.Command)
	}

	smtpDebug(ansi.LightGreen, serviceSMTP, h.conversation.Ident, "requests", len(h.smtpRequests), "responses", len(h.smtpResponses), ansi.Reset)

	mails := h.processSMTPConversation()

	smtpMsg := &types.SMTP{
		Timestamp: h.conversation.FirstClientPacket.UnixNano(),
		SrcIP:     h.conversation.ClientIP,
		DstIP:     h.conversation.ServerIP,
		SrcPort:   h.conversation.ClientPort,
		DstPort:   h.conversation.ServerPort,
		MailIDs:   mails,
		Commands:  commands,
	}

	// export metrics if configured
	if decoderconfig.Instance.ExportMetrics {
		smtpMsg.Inc()
	}

	// write record to disk
	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(smtpMsg)
	if err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}
}

func smtpDebug(args ...interface{}) {
	smtpLogSugared.Info(args...)
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
		smtpLog.Error("SMTP Request error",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)

		return err
	}

	smtpDebug(ansi.Red, h.conversation.Ident, "readSMTPRequest", line, ansi.Reset)

	cmd, args := getSMTPCommand(line)

	if cmd == smtpDot {

		smtpDebug("collected data", strings.Join(data, "\n"))

		h.smtpRequests = append(h.smtpRequests, &types.SMTPRequest{
			Command: smtpDATA,
			Data:    strings.Join(data, "\n"),
		})

		return nil
	}

	if validSMTPCommand(cmd) {

		if cmd == smtpDATA {
			goto nextLine
		}

		h.smtpRequests = append(h.smtpRequests, &types.SMTPRequest{
			Command:  cmd,
			Argument: strings.Join(args, " "),
			Data:     strings.Join(data, "\n"),
		})

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
		if len(cmd) > 1 {
			cmd[1] = strings.Trim(cmd[1], "<>")
		}
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
		smtpLog.Error(
			"failed to read next SMTP response line",
			zap.String("ident", h.conversation.Ident),
			zap.Error(err),
		)
		return err
	}

	smtpDebug(ansi.Blue, h.conversation.Ident, "readSMTPResponse", line, ansi.Reset)

	cmd, args = getSMTPCommand(line)

	// handle data in response
	if strings.Contains(cmd, "-") {
		// more to come
		data = append(data, line)
		goto nextLine
	}

	code, err := strconv.Atoi(cmd)
	if err != nil {
		smtpDebug(ansi.Red, h.conversation.Ident, "invalid response code", cmd)
	}

	h.smtpResponses = append(h.smtpResponses, &types.SMTPResponse{
		ResponseCode: int32(code),
		Parameter:    strings.Join(args, " "),
		Data:         strings.Join(data, "\n"),
	})

	// if QUIT was acked - quit
	if code == smtpOK && strings.Contains(args[len(args)-1], smtpQUIT) {
		return io.EOF
	}

	return nil
}

// process the SMTP conversation and returns a list of extracted mail identifiers
func (h *smtpReader) processSMTPConversation() (mailIDs []string) {
	if len(h.smtpResponses) == 0 || len(h.smtpRequests) == 0 {
		return
	}

	var (
		// state    = stateNotAuthenticated
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

			m := mail.Parse(h.conversation, []byte(r.Data), from, to, smtpLogSugared, serviceSMTP)
			mail.WriteMail(m)
			mailIDs = append(mailIDs, m.ID)
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
