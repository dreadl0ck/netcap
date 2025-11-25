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

package syslog

import (
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type syslogReader struct {
	conversation *core.ConversationInfo
}

// New returns a new syslog reader.
func (s *syslogReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &syslogReader{
		conversation: conversation,
	}
}

// Syslog facility names
var facilityNames = []string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

// Syslog severity names
var severityNames = []string{
	"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
}

// RFC 3164 BSD syslog format regex
var rfc3164Regex = regexp.MustCompile(`^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)`)

// RFC 5424 syslog format regex
// Format: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [STRUCTURED-DATA] MSG
// Example: <165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"] BOMAn application event log entry...
var rfc5424Regex = regexp.MustCompile(`^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(-|\[.*?\])\s*(.*)`)

// Security-relevant keywords
var securityKeywords = []string{
	"authentication", "auth", "login", "logout", "failed", "denied",
	"unauthorized", "access", "permission", "security", "password",
	"sudo", "ssh", "firewall", "intrusion", "attack", "malware",
	"virus", "exploit", "vulnerability", "breach", "violation",
}

// Decode parses syslog messages from the stream.
func (s *syslogReader) Decode() {
	if Decoder.Writer == nil {
		syslogLog.Error("Syslog Decoder.Writer is nil")
		return
	}

	for _, d := range s.conversation.Data {
		raw := d.Raw()
		if len(raw) < 4 {
			continue
		}

		msg := s.parseSyslogMessage(raw)
		if msg != nil {
			msg.SrcIP = s.conversation.ClientIP
			msg.DstIP = s.conversation.ServerIP
			msg.SrcPort = int32(s.conversation.ClientPort)
			msg.DstPort = int32(s.conversation.ServerPort)
			msg.Protocol = "UDP"

			err := Decoder.Writer.Write(msg)
			if err != nil {
				syslogLog.Error("failed to write syslog record", zap.Error(err))
			} else {
				atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
			}
		}
	}
}

func (s *syslogReader) parseSyslogMessage(data []byte) *types.Syslog {
	msg := string(data)

	// Try RFC 5424 format first
	if matches := rfc5424Regex.FindStringSubmatch(msg); len(matches) > 0 {
		return s.parseRFC5424(matches)
	}

	// Try RFC 3164 (BSD) format
	if matches := rfc3164Regex.FindStringSubmatch(msg); len(matches) > 0 {
		return s.parseRFC3164(matches)
	}

	// Fallback: try to at least parse the PRI field
	return s.parsePRIOnly(msg)
}

func (s *syslogReader) parseRFC3164(matches []string) *types.Syslog {
	priority, _ := strconv.Atoi(matches[1])
	facility := priority / 8
	severity := priority % 8

	var processID int32
	if matches[5] != "" {
		pid, _ := strconv.Atoi(matches[5])
		processID = int32(pid)
	}

	message := matches[6]
	isSecurityRelevant := s.checkSecurityRelevance(message)

	return &types.Syslog{
		Timestamp:           s.conversation.FirstClientPacket.UnixNano(),
		Priority:            int32(priority),
		Facility:            int32(facility),
		FacilityName:        getFacilityName(facility),
		Severity:            int32(severity),
		SeverityName:        getSeverityName(severity),
		BSDTimestamp:        matches[2],
		Hostname:            matches[3],
		Tag:                 matches[4],
		ProcessID:           processID,
		Message:             message,
		IsSecurityRelevant:  isSecurityRelevant,
	}
}

func (s *syslogReader) parseRFC5424(matches []string) *types.Syslog {
	priority, _ := strconv.Atoi(matches[1])
	facility := priority / 8
	severity := priority % 8
	version, _ := strconv.Atoi(matches[2])

	message := matches[9]
	isSecurityRelevant := s.checkSecurityRelevance(message)

	// RFC 5424 field order: PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, SD, MSG
	var appName, msgID string
	var processID int32
	if matches[5] != "-" {
		appName = matches[5]
	}
	if matches[6] != "-" {
		pid, err := strconv.Atoi(matches[6])
		if err == nil {
			processID = int32(pid)
		}
	}
	if matches[7] != "-" {
		msgID = matches[7]
	}

	return &types.Syslog{
		Timestamp:           s.conversation.FirstClientPacket.UnixNano(),
		Priority:            int32(priority),
		Facility:            int32(facility),
		FacilityName:        getFacilityName(facility),
		Severity:            int32(severity),
		SeverityName:        getSeverityName(severity),
		Hostname:            matches[4],
		AppName:             appName,
		ProcessID:           processID,
		MsgID:               msgID,
		Message:             message,
		Version:             int32(version),
		IsSecurityRelevant:  isSecurityRelevant,
	}
}

func (s *syslogReader) parsePRIOnly(msg string) *types.Syslog {
	if len(msg) < 3 || msg[0] != '<' {
		return nil
	}

	// Find closing '>'
	endIdx := strings.Index(msg, ">")
	if endIdx < 2 || endIdx > 4 {
		return nil
	}

	priority, err := strconv.Atoi(msg[1:endIdx])
	if err != nil {
		return nil
	}

	facility := priority / 8
	severity := priority % 8
	message := msg[endIdx+1:]

	isSecurityRelevant := s.checkSecurityRelevance(message)

	return &types.Syslog{
		Timestamp:          s.conversation.FirstClientPacket.UnixNano(),
		Priority:           int32(priority),
		Facility:           int32(facility),
		FacilityName:       getFacilityName(facility),
		Severity:           int32(severity),
		SeverityName:       getSeverityName(severity),
		Message:            strings.TrimSpace(message),
		IsSecurityRelevant: isSecurityRelevant,
	}
}

func (s *syslogReader) checkSecurityRelevance(message string) bool {
	msgLower := strings.ToLower(message)
	for _, keyword := range securityKeywords {
		if strings.Contains(msgLower, keyword) {
			return true
		}
	}
	return false
}

func getFacilityName(facility int) string {
	if facility >= 0 && facility < len(facilityNames) {
		return facilityNames[facility]
	}
	return "unknown"
}

func getSeverityName(severity int) string {
	if severity >= 0 && severity < len(severityNames) {
		return severityNames[severity]
	}
	return "unknown"
}

