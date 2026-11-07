package tls

import (
	"bytes"
	"strings"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

// ObserveUpgrade shares the TLS framer with validated cleartext protocol hand-offs.
func ObserveUpgrade(c *core.ConversationInfo, primary string) {
	if !helloEnabled() && RecordDecoder.Writer == nil && Decoder.Writer == nil {
		return
	}
	if primary == Decoder.Name {
		return
	}
	fragments := c.Data
	if fragments == nil {
		fragments = core.MergeByTimestamp(c.ClientData, c.ServerData)
	}
	client, server := c.ClientData, c.ServerData
	if client == nil && server == nil {
		for _, f := range fragments {
			if fragmentSide(f) == 0 {
				client = append(client, f)
			} else {
				server = append(server, f)
			}
		}
	}
	if helloPrefixType(client) == 1 || helloPrefixType(server) == 1 {
		(&tlsReader{conversation: c}).frameConversation()
		return
	}
	bounds, ok := negotiatedUpgrade(fragments, primary)
	if !ok {
		return
	}
	copy := *c
	copy.Data, copy.ClientData, copy.ServerData = nil, nil, nil
	var positions [2]int
	for _, f := range fragments {
		side := fragmentSide(f)
		start := positions[side]
		positions[side] += len(f.Raw())
		if positions[side] < bounds[side] || positions[side] == bounds[side] && len(f.Raw()) > 0 {
			continue
		}
		d := &core.StreamData{RawData: f.Raw()[max(0, bounds[side]-start):], Dir: f.Direction(), AssemblerContext: f.Context(), CaptureInformation: f.CaptureInfo()}
		if original, ok := f.(*core.StreamData); ok {
			d.SkippedBytes = original.SkippedBytes
			if start < bounds[side] {
				d.SkippedBytes = 0
			}
		}
		copy.Data = append(copy.Data, d)
		if side == 0 {
			copy.ClientData = append(copy.ClientData, d)
		} else {
			copy.ServerData = append(copy.ServerData, d)
		}
	}
	if helloPrefixType(copy.ClientData) == 0 && helloPrefixType(copy.ServerData) == 0 {
		return
	}
	(&tlsReader{conversation: &copy}).frameConversation()
}

func fragmentSide(f core.DataFragment) int {
	if f.Direction() == reassembly.TCPDirServerToClient {
		return 1
	}
	return 0
}

func cleartextUpgrade(fragments core.DataFragments) ([2]int, bool) {
	var lines [2][]byte
	var consumed [2]int
	var seen [2]int
	pending, requestSide, requestEnd, tag := "", 0, 0, ""
	var smtpData [2]bool
	for _, f := range fragments {
		side := fragmentSide(f)
		if pending != "" && side == requestSide {
			// Everything after the command belongs to the proposed TLS stream.
			continue
		}
		if d, ok := f.(*core.StreamData); ok && d.SkippedBytes != 0 && (d.SkippedBytes > 0 || seen[side] > 0) {
			return [2]int{}, false
		}
		if seen[side] >= maxUpgradeBytes {
			return [2]int{}, false
		}
		n := min(len(f.Raw()), maxUpgradeBytes-seen[side])
		seen[side] += n
		lines[side] = append(lines[side], f.Raw()[:n]...)
		for {
			end := bytes.IndexByte(lines[side], '\n')
			if end < 0 {
				if len(lines[side]) > 8192 {
					return [2]int{}, false
				}
				break
			}
			if end > 8192 {
				return [2]int{}, false
			}
			line := strings.TrimSuffix(string(lines[side][:end]), "\r")
			lines[side] = lines[side][end+1:]
			consumed[side] += end + 1
			if smtpData[side] {
				if line == "." {
					smtpData[side] = false
				}
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if pending != "" && side != requestSide {
				ready := pending == "smtp" && (line == "220" || strings.HasPrefix(line, "220 ")) || pending == "pop3" && (line == "+OK" || strings.HasPrefix(line, "+OK ")) || pending == "ftp" && (line == "234" || strings.HasPrefix(line, "234 ")) || pending == "imap" && len(fields) > 1 && fields[0] == tag && strings.EqualFold(fields[1], "OK")
				if ready {
					var bounds [2]int
					bounds[requestSide] = requestEnd
					bounds[side] = consumed[side]
					return bounds, true
				}
				if strings.HasPrefix(line, "4") || strings.HasPrefix(line, "5") || strings.HasPrefix(line, "-ERR") || pending == "imap" && fields[0] == tag {
					pending = ""
				}
			}
			switch {
			case len(fields) == 1 && strings.EqualFold(fields[0], "STARTTLS"):
				pending = "smtp"
			case len(fields) == 1 && strings.EqualFold(fields[0], "STLS"):
				pending = "pop3"
			case len(fields) == 2 && strings.EqualFold(fields[1], "STARTTLS"):
				pending, tag = "imap", fields[0]
			case len(fields) == 2 && strings.EqualFold(fields[0], "AUTH") && strings.EqualFold(fields[1], "TLS"):
				pending = "ftp"
			case len(fields) == 1 && strings.EqualFold(fields[0], "DATA"):
				smtpData[side] = true
				continue
			default:
				continue
			}
			requestSide, requestEnd = side, consumed[side]
			break
		}
	}
	return [2]int{}, false
}

func socksMessageLength(b []byte) int {
	if len(b) < 4 || b[0] != 5 || b[2] != 0 {
		return 0
	}
	switch b[3] {
	case 1:
		if len(b) >= 10 {
			return 10
		}
	case 4:
		if len(b) >= 22 {
			return 22
		}
	case 3:
		if len(b) >= 5 && b[4] > 0 && len(b) >= 7+int(b[4]) {
			for _, v := range b[5 : 5+int(b[4])] {
				if v < 33 || v > 126 {
					return 0
				}
			}
			return 7 + int(b[4])
		}
	}
	return 0
}

func socksUpgrade(fragments core.DataFragments) ([2]int, bool) {
	return tryUpgrade(upgradePrefixes(fragments), socksBounds)
}
