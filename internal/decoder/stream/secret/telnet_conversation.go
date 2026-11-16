package secret

import (
	"bytes"

	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

func HarvestTelnetConversation(c *core.ConversationInfo) {
	if !useHarvesters || Decoder.Writer == nil || c == nil {
		return
	}
	enabled := false
	for _, h := range tcpConnectionHarvesters {
		if h.Name == "Telnet" {
			enabled = true
			break
		}
	}
	if !enabled || decoderconfig.Instance.HarvesterPortFilter && !harvesterMatchesPort("Telnet", int(c.ClientPort), int(c.ServerPort)) && !telnetPromptEvidence(c) {
		return
	}
	parseTelnetAuth(c, func(record *types.Secret) {
		record.Flow = c.Ident
		record.CommunityID = c.CommunityID
		WriteSecret(record)
	})
}

func telnetPromptEvidence(c *core.ConversationInfo) bool {
	var prefix []byte
collect:
	for _, fragment := range c.Data {
		if !core.FromServer(fragment) {
			continue
		}
		if data, ok := fragment.(*core.StreamData); ok && (data.SkippedBytes != 0 || data.DiscardedBytes != 0) {
			prefix = nil
		}
		for _, b := range fragment.Raw() {
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			prefix = append(prefix, b)
			if len(prefix) == 4096 {
				break collect
			}
		}
	}
	for _, pattern := range getTelnetLoginPatterns() {
		if pattern != "" && bytes.Contains(prefix, bytes.ToLower([]byte(pattern))) {
			return true
		}
	}
	return false
}

type telnetText struct{ state uint8 }

func (s *telnetText) consume(b byte) (byte, bool) {
	switch s.state {
	case 1:
		s.state = 0
		switch b {
		case 255:
			return b, true
		case 251, 252, 253, 254:
			s.state = 2
		case 250:
			s.state = 3
		}
		return 0, false
	case 2:
		s.state = 0
		return 0, false
	case 3:
		if b == 255 {
			s.state = 4
		}
		return 0, false
	case 4:
		if b == 240 {
			s.state = 0
		} else {
			s.state = 3
		}
		return 0, false
	}
	if b == 255 {
		s.state = 1
		return 0, false
	}
	return b, b != 0
}

func parseTelnetAuth(c *core.ConversationInfo, emit func(*types.Secret)) {
	var text [2]telnetText
	var prompt, line []byte
	stage := 0
	user := ""
	processed, emitted := 0, 0
	maxPrompt := 1
	normalize := func(patterns []string) [][]byte {
		result := make([][]byte, 0, len(patterns))
		for _, pattern := range patterns {
			value := []byte(pattern)
			for i, b := range value {
				if b >= 'A' && b <= 'Z' {
					value[i] = b + ('a' - 'A')
				}
			}
			if len(value) > maxPrompt {
				maxPrompt = len(value)
			}
			if len(value) > 0 {
				result = append(result, value)
			}
		}
		return result
	}
	loginPatterns := normalize(getTelnetLoginPatterns())
	passwordPatterns := normalize(getTelnetPasswordPatterns())
	matches := func(patterns [][]byte) bool {
		for _, pattern := range patterns {
			if bytes.HasSuffix(prompt, pattern) {
				return true
			}
		}
		return false
	}
	for _, fragment := range c.Data {
		side := 0
		if core.FromServer(fragment) {
			side = 1
		}
		if data, ok := fragment.(*core.StreamData); ok && (data.SkippedBytes != 0 || data.DiscardedBytes != 0) {
			stage = 0
			user = ""
			line = nil
			prompt = nil
			text = [2]telnetText{}
		}
		for _, wireByte := range fragment.Raw() {
			processed++
			if processed > 64<<10 || emitted >= 64 {
				return
			}
			b, ok := text[side].consume(wireByte)
			if !ok {
				continue
			}
			if side == 1 {
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				if len(prompt) == maxPrompt {
					copy(prompt, prompt[1:])
					prompt = prompt[:len(prompt)-1]
				}
				prompt = append(prompt, b)
				if matches(loginPatterns) {
					stage = 1
					user = ""
					line = nil
					prompt = nil
				} else if stage == 3 && matches(passwordPatterns) {
					stage = 2
					line = nil
					prompt = nil
				}
				continue
			}
			if stage != 1 && stage != 2 {
				continue
			}
			if b == 8 || b == 127 {
				if len(line) > 0 {
					line = line[:len(line)-1]
				}
				continue
			}
			if b == '\r' || b == '\n' {
				if len(line) == 0 {
					continue
				}
				if stage == 1 {
					user = string(line)
					stage = 3
				} else {
					emit(&types.Secret{Timestamp: core.FragmentTime(fragment), Service: serviceTelnet, User: user, Password: string(line), Notes: "Observed Telnet login exchange; NUL padding and negotiation removed; authentication outcome unknown"})
					emitted++
					stage = 0
					user = ""
				}
				line = nil
				continue
			}
			line = append(line, b)
			if len(line) > 4096 {
				stage = 0
				line = nil
				user = ""
			}
		}
	}
}
