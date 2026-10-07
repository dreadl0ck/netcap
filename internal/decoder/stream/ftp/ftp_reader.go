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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package ftp

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	streamutils "github.com/dreadl0ck/netcap/internal/decoder/stream/utils"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/types"
)

type ftpReader struct {
	conversation                                              *core.ConversationInfo
	timestamp                                                 int64
	lastCommand, lastFilename, username, transferMode, dataIP string
	dataPort                                                  int
	isPassive, protected                                      bool
	fileSize                                                  int64
	multiline                                                 int
	pending                                                   *dataTransfer
}

func (f *ftpReader) New(c *core.ConversationInfo) core.StreamDecoderInterface {
	return &ftpReader{conversation: c}
}

func (f *ftpReader) Decode() {
	streamutils.DecodeConversationAt(f.conversation.Ident, f.conversation.Data, f.readClient, f.readServer)
	f.finishTransfer()
}

func (f *ftpReader) finishTransfer() {
	if f.pending != nil {
		registerTransfer(*f.pending)
		f.pending = nil
	}
}

func (f *ftpReader) readClient(b *bufio.Reader, pos *streamutils.ReadPosition) error {
	f.timestamp = pos.Timestamp()
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
	command, arg := strings.ToUpper(parts[0]), ""
	if len(parts) == 2 {
		arg = strings.TrimSpace(parts[1])
	}
	f.lastCommand = command
	switch command {
	case "USER":
		f.username = arg
	case "TYPE":
		f.transferMode = map[string]string{"A": "ASCII", "I": "BINARY", "E": "EBCDIC"}[arg]
	case "PROT":
		f.protected = strings.EqualFold(arg, "P")
	case "PORT":
		f.dataIP, f.dataPort = parseEndpoint(arg)
		f.isPassive = false
	case "PASV", "EPSV":
		f.dataIP, f.dataPort = "", 0
		f.isPassive = true
	case "EPRT":
		f.dataIP, f.dataPort = "", 0
		f.isPassive = false
		if len(arg) > 0 {
			p := strings.Split(arg, arg[:1])
			if len(p) == 5 && p[4] == "" && (p[1] == "1" || p[1] == "2") && net.ParseIP(p[2]) != nil {
				ip := net.ParseIP(p[2])
				port, e := strconv.Atoi(p[3])
				if e == nil && port > 0 && port <= 65535 && (p[1] == "1") == (ip.To4() != nil) {
					f.dataIP, f.dataPort = ip.String(), port
				}
			}
		}
	case "SIZE":
		f.lastFilename = arg
	case "RETR", "STOR":
		f.finishTransfer()
		f.lastFilename = arg
		if f.dataPort != 0 && !f.protected {
			f.pending = &dataTransfer{ControlID: f.conversation.Ident, ControlCommunityID: f.conversation.CommunityID, ClientIP: f.conversation.ClientIP, ServerIP: f.conversation.ServerIP, IP: f.dataIP, Port: int32(f.dataPort), Passive: f.isPassive, Command: command, Filename: arg, Start: f.timestamp, End: f.timestamp + int64(5*time.Minute)}
		}
	}
	f.writeFTPRecord(false, command, arg, 0, "")
	return nil
}

func parseEndpoint(s string) (string, int) {
	p := strings.Split(s, ",")
	if len(p) != 6 {
		return "", 0
	}
	var n [6]uint64
	for i, v := range p {
		x, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return "", 0
		}
		n[i] = x
	}
	port := int(n[4]*256 + n[5])
	if port == 0 {
		return "", 0
	}
	return fmt.Sprintf("%d.%d.%d.%d", n[0], n[1], n[2], n[3]), port
}

func (f *ftpReader) readServer(b *bufio.Reader, pos *streamutils.ReadPosition) error {
	f.timestamp = pos.Timestamp()
	line, err := b.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if len(line) < 3 {
		return nil
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return nil
	}
	message := ""
	if len(line) > 4 {
		message = line[4:]
	}
	// Only the terminating reply line changes transfer state.
	final := len(line) >= 4 && line[3] == ' '
	if len(line) >= 4 && line[3] == '-' && f.multiline == 0 {
		f.multiline = code
		final = false
	}
	if f.multiline != 0 {
		final = final && code == f.multiline
		if final {
			f.multiline = 0
		}
	}
	if final {
		switch code {
		case 125, 150:
			if f.pending != nil {
				f.pending.Accepted = true
			}
		case 226, 250:
			if f.pending != nil {
				f.pending.Complete = true
				f.pending.End = f.timestamp
				f.finishTransfer()
			}
			f.dataIP, f.dataPort = "", 0
		case 421, 425, 426, 450, 451, 452, 500, 501, 502, 530, 550, 551, 552, 553:
			if f.pending != nil {
				f.pending.End = f.timestamp
				f.finishTransfer()
			}
			f.dataIP, f.dataPort = "", 0
		case 213:
			f.fileSize, _ = strconv.ParseInt(message, 10, 64)
		case 227:
			f.dataIP, f.dataPort = "", 0
			if _, tail, ok := strings.Cut(message, "("); ok {
				s, _, ok := strings.Cut(tail, ")")
				if ok {
					f.dataIP, f.dataPort = parseEndpoint(s)
				}
			}
			f.isPassive = true
		case 229:
			f.dataIP, f.dataPort = "", 0
			f.isPassive = true
			if _, tail, ok := strings.Cut(message, "("); ok && len(tail) > 0 {
				s, _, ok := strings.Cut(tail, ")")
				if ok && len(s) > 0 {
					p := strings.Split(s, s[:1])
					if len(p) == 5 && p[1] == "" && p[2] == "" && p[4] == "" {
						port, e := strconv.Atoi(p[3])
						if e == nil && port > 0 && port <= 65535 {
							f.dataIP, f.dataPort = f.conversation.ServerIP, port
						}
					}
				}
			}
		}
	}
	f.writeFTPRecord(true, "", "", int32(code), message)
	return nil
}

func (f *ftpReader) writeFTPRecord(response bool, command, arg string, code int32, message string) {
	if Decoder.Writer == nil {
		return
	}
	mode := "UNKNOWN"
	if f.isPassive {
		mode = "PASSIVE"
	} else if f.dataIP != "" {
		mode = "ACTIVE"
	}
	src, dst, sp, dp := f.conversation.ClientIP, f.conversation.ServerIP, f.conversation.ClientPort, f.conversation.ServerPort
	if response {
		src, dst, sp, dp = dst, src, dp, sp
	}
	r := &types.FTP{Timestamp: f.timestamp, SrcIP: src, DstIP: dst, SrcPort: sp, DstPort: dp, IsResponse: response, Command: command, Argument: arg, ResponseCode: code, ResponseMessage: message, Filename: f.lastFilename, TransferMode: f.transferMode, DataConnectionMode: mode, DataIP: f.dataIP, DataPort: int32(f.dataPort), Username: f.username, IsControl: true, FileSize: f.fileSize, CommunityID: f.conversation.CommunityID}
	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	if err := Decoder.Writer.Write(r); err != nil {
		decoderutils.ErrorMap.Inc(err.Error())
	}
}
