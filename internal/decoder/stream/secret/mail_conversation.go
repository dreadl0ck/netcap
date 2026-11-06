package secret

import (
	"bytes"
	"encoding/base64"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
	"github.com/dreadl0ck/netcap/types"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

func writeConversationSecret(s *types.Secret) {
	if Decoder.Writer != nil && Decoder.Writer.Write(s) == nil {
		atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
	}
}
func HarvestAdditionalConversation(c *core.ConversationInfo) {
	if Decoder.Writer == nil || !useHarvesters {
		return
	}
	for _, h := range tcpConnectionHarvesters {
		if h.Name == "POP3" || h.Name == "IMAP" {
			if !decoderconfig.Instance.HarvesterPortFilter || harvesterMatchesPort(h.Name, int(c.ClientPort), int(c.ServerPort)) {
				parseMailAuth(c, h.Name, writeConversationSecret)
			}
		}
		if h.Name == "NTLMSSP" {
			if !decoderconfig.Instance.HarvesterPortFilter || harvesterMatchesPort(h.Name, int(c.ClientPort), int(c.ServerPort)) {
				harvestNTLMIdentity(c, writeConversationSecret)
			}
		}
	}
}

func authWords(line string) ([]string, bool) {
	var words []string
	for len(line) > 0 {
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			break
		}
		if line[0] != '"' {
			word, rest, ok := strings.Cut(line, " ")
			words = append(words, word)
			if !ok {
				break
			}
			line = rest
			continue
		}
		line = line[1:]
		var word strings.Builder
		closed := false
		for len(line) > 0 {
			b := line[0]
			line = line[1:]
			if b == '"' {
				closed = true
				break
			}
			if b == '\\' {
				if line == "" {
					return nil, false
				}
				b = line[0]
				line = line[1:]
			}
			word.WriteByte(b)
		}
		if !closed {
			return nil, false
		}
		words = append(words, word.String())
	}
	return words, true
}

func parseMailAuth(c *core.ConversationInfo, protocol string, emit func(*types.Secret)) {
	var buffers [2][]byte
	var seen [2]bool
	client := 0
	if protocol == "POP3" && (c.ClientPort == 110 || c.ClientPort == 995) || protocol == "IMAP" && (c.ClientPort == 143 || c.ClientPort == 993) {
		client = 1
	}
	active := protocol == "POP3" && (c.ServerPort == 110 || c.ServerPort == 995 || client == 1) || protocol == "IMAP" && (c.ServerPort == 143 || c.ServerPort == 993 || client == 1)
	user, mechanism, tag, upgradeTag := "", "", "", ""
	stage := 0
	var at int64
	var pending *types.Secret
	flush := func() {
		if pending != nil {
			emit(pending)
			pending = nil
		}
	}
	defer flush()
	for _, f := range c.Data {
		i := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			i = 1
		}
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 && (d.SkippedBytes > 0 || seen[i]) {
			return
		}
		seen[i] = true
		if len(buffers[i])+len(f.Raw()) > 65536 {
			return
		}
		buffers[i] = append(buffers[i], f.Raw()...)
		for {
			end := bytes.IndexByte(buffers[i], '\n')
			if end < 0 {
				break
			}
			line := strings.TrimSuffix(string(buffers[i][:end]), "\r")
			buffers[i] = buffers[i][end+1:]
			if len(line) > 8192 || !utf8.ValidString(line) || strings.ContainsRune(line, 0) {
				return
			}
			if i != client {
				words := strings.Fields(line)
				if len(words) == 0 {
					continue
				}
				if protocol == "POP3" && strings.HasPrefix(line, "+OK") || protocol == "IMAP" && len(words) > 1 && words[0] == "*" && strings.EqualFold(words[1], "OK") {
					active = true
				}
				if upgradeTag != "" {
					if protocol == "POP3" && words[0] == "+OK" || protocol == "IMAP" && len(words) > 1 && words[0] == upgradeTag && strings.EqualFold(words[1], "OK") {
						return
					}
					if protocol == "POP3" && words[0] == "-ERR" || protocol == "IMAP" && words[0] == upgradeTag {
						upgradeTag = ""
					}
				}
				result := protocol == "POP3" && (words[0] == "+OK" || words[0] == "-ERR") || protocol == "IMAP" && len(words) > 1 && words[0] == tag
				if pending != nil && result {
					pending.AuthSuccessSet = true
					pending.AuthSuccess = words[0] == "+OK" || len(words) > 1 && strings.EqualFold(words[1], "OK")
					success := pending.AuthSuccess
					flush()
					stage = 0
					user = ""
					if success {
						return
					}
				}
				continue
			}
			if !active {
				continue
			}
			words, ok := authWords(line)
			if !ok || len(words) == 0 {
				continue
			}
			command := strings.ToUpper(words[0])
			args := words[1:]
			if protocol == "IMAP" {
				if len(words) >= 2 && (strings.EqualFold(words[1], "LOGIN") || strings.EqualFold(words[1], "AUTHENTICATE") || strings.EqualFold(words[1], "STARTTLS")) {
					tag = words[0]
					command = strings.ToUpper(words[1])
					args = words[2:]
				}
			}
			if command == "STLS" && protocol == "POP3" || command == "STARTTLS" && protocol == "IMAP" {
				upgradeTag = tag
				if protocol == "POP3" {
					upgradeTag = "STLS"
				}
				stage = 0
				user = ""
				continue
			}
			makeSecret := func(name, password, mode string) {
				flush()
				pending = &types.Secret{Timestamp: at, Service: protocol + " Auth " + mode, Flow: c.Ident, CommunityID: c.CommunityID, User: name, Password: password}
				stage = 0
				user = ""
			}
			if protocol == "POP3" && command == "USER" && len(args) == 1 {
				user = args[0]
				at = core.FragmentTime(f)
				continue
			}
			if protocol == "POP3" && command == "PASS" && user != "" {
				makeSecret(user, strings.TrimPrefix(line, "PASS "), "UserPass")
				continue
			}
			if protocol == "IMAP" && command == "LOGIN" && len(args) == 2 {
				at = core.FragmentTime(f)
				makeSecret(args[0], args[1], "Login")
				continue
			}
			if command == "AUTH" && protocol == "POP3" || command == "AUTHENTICATE" && protocol == "IMAP" {
				flush()
				stage = 0
				user = ""
				if len(args) == 0 {
					continue
				}
				mechanism = strings.ToUpper(args[0])
				if mechanism != "PLAIN" && mechanism != "LOGIN" && mechanism != "CRAM-MD5" {
					continue
				}
				stage = 1
				at = core.FragmentTime(f)
				if len(args) < 2 {
					continue
				}
				line = args[1]
			} else if stage == 0 {
				continue
			}
			if line == "*" {
				stage = 0
				user = ""
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(line)
			if err != nil || !utf8.Valid(decoded) {
				stage = 0
				user = ""
				continue
			}
			switch mechanism {
			case "PLAIN":
				parts := bytes.Split(decoded, []byte{0})
				if len(parts) == 3 && len(parts[1]) > 0 {
					makeSecret(string(parts[1]), string(parts[2]), "Plain")
				}
			case "LOGIN":
				if stage == 1 {
					user = string(decoded)
					stage = 2
				} else {
					makeSecret(user, string(decoded), "Login")
				}
			case "CRAM-MD5":
				parts := strings.Fields(string(decoded))
				if len(parts) == 2 {
					makeSecret(parts[0], parts[1], "CRAM-MD5")
				}
			}
		}
	}
}
