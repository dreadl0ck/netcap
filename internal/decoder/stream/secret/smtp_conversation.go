package secret

import (
	"bytes"
	"encoding/base64"
	"go.uber.org/zap"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
)

// SMTP auth needs the full ordered exchange, not a truncated service banner.
func HarvestSMTPConversation(c *core.ConversationInfo) {
	if Decoder.Writer == nil || !useHarvesters {
		return
	}
	enabled := false
	for _, h := range tcpConnectionHarvesters {
		if h.Name == "SMTP" {
			enabled = true
		}
	}
	if !enabled {
		return
	}
	if decoderconfig.Instance.HarvesterPortFilter && !harvesterMatchesPort("SMTP", int(c.ClientPort), int(c.ServerPort)) {
		return
	}
	parseSMTPAuth(c, func(s *types.Secret) {
		if err := Decoder.Writer.Write(s); err == nil {
			if decoderconfig.Instance.ExportMetrics {
				s.Inc()
			}
			atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
		} else {
			credLog.Error("writing SMTP authentication observation", zap.Error(err))
		}
	})
}

func parseSMTPAuth(c *core.ConversationInfo, emit func(*types.Secret)) {
	type side struct {
		data []byte
		at   int64
	}
	var sides [2]side
	mechanism, stage, user := "", 0, ""
	var at int64
	var pending *types.Secret
	dataMode, awaitData, upgrade, encrypted := false, false, false, false
	flush := func(result string) {
		if pending != nil {
			pending.Notes = "SMTP authentication exchange: " + result
			emit(pending)
			pending = nil
		}
	}
	reset := func() { mechanism = ""; stage = 0; user = "" }
	for _, f := range c.Data {
		if encrypted {
			break
		}
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 {
			flush("capture gap; result unknown")
			reset()
			sides = [2]side{}
			dataMode = false
			awaitData = false
			upgrade = false
		}
		i := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			i = 1
		}
		s := &sides[i]
		if len(s.data) == 0 {
			s.at = core.FragmentTime(f)
		}
		if len(s.data)+len(f.Raw()) > 1<<20 {
			flush("line limit; result unknown")
			return
		}
		s.data = append(s.data, f.Raw()...)
		for {
			end := bytes.IndexByte(s.data, '\n')
			if end < 0 {
				break
			}
			line := strings.TrimSuffix(string(s.data[:end]), "\r")
			timestamp := s.at
			s.data = s.data[end+1:]
			s.at = core.FragmentTime(f)
			if len(line) > 64<<10 {
				flush("line limit; result unknown")
				return
			}
			if i == 1 {
				if strings.HasPrefix(line, "235 ") {
					flush("success")
					reset()
				}
				if len(line) >= 3 && line[0] >= '4' && line[0] <= '5' {
					if awaitData {
						dataMode = false
					}
					flush("rejected")
					reset()
					awaitData = false
					upgrade = false
				}
				if upgrade && strings.HasPrefix(line, "220 ") {
					flush("upgrade; result unknown")
					encrypted = true
					break
				}
				if awaitData && strings.HasPrefix(line, "354 ") {
					dataMode = true
					awaitData = false
				}
				continue
			}
			if dataMode {
				if line == "." {
					dataMode = false
				}
				continue
			}
			words := strings.Fields(line)
			if len(words) == 0 {
				continue
			}
			command := strings.ToUpper(words[0])
			if command == "STARTTLS" {
				upgrade = true
				reset()
				continue
			}
			if command == "DATA" {
				awaitData = true
				dataMode = true
				continue
			}
			if command == "AUTH" {
				flush("next exchange; result unknown")
				reset()
				at = timestamp
				if len(words) < 2 {
					continue
				}
				mechanism = strings.ToUpper(words[1])
				if mechanism != "PLAIN" && mechanism != "LOGIN" {
					reset()
					continue
				}
				stage = 1
				if len(words) < 3 {
					continue
				}
				line = words[2]
			} else if stage == 0 {
				continue
			}
			if line == "*" {
				reset()
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(line)
			if err != nil || !utf8.Valid(decoded) {
				reset()
				continue
			}
			password := ""
			if mechanism == "PLAIN" {
				parts := bytes.Split(decoded, []byte{0})
				if len(parts) != 3 || len(parts[1]) == 0 {
					reset()
					continue
				}
				user, password = string(parts[1]), string(parts[2])
			} else if stage == 1 {
				user = string(decoded)
				stage = 2
				continue
			} else {
				password = string(decoded)
			}
			service := "SMTP Auth Plain"
			if mechanism == "LOGIN" {
				service = "SMTP Auth Login"
			}
			pending = &types.Secret{Timestamp: at, Service: service, Flow: c.Ident, CommunityID: c.CommunityID, User: user, Password: password}
			reset()
		}
	}
	flush("capture ended; result unknown")
}
