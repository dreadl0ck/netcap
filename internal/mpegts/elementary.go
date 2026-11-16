package mpegts

import (
	"bytes"
	"encoding/binary"
)

func pts(data []byte, prefix byte) (uint64, bool) {
	if len(data) < 5 || data[0]>>4 != prefix || data[0]&1 == 0 || data[2]&1 == 0 || data[4]&1 == 0 {
		return 0, false
	}
	return uint64(data[0]>>1&7)<<30 | uint64(data[1])<<22 | uint64(data[2]>>1)<<15 | uint64(data[3])<<7 | uint64(data[4]>>1), true
}

func pes(state *pidState, pid uint16, stream Stream, data []byte, start bool, source Source) []Event {
	var events []Event
	if start {
		state.pesHeader = nil
		state.pesReady = false
		state.pesStarted = true
		state.es = nil
		state.esSources = nil
		state.pesSources = nil
	}
	if !state.pesStarted {
		return nil
	}
	if !state.pesReady {
		if len(state.pesSources) >= 128 {
			state.pesStarted = false
			return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"header-source-limit"}}}
		}
		state.pesSources = append(state.pesSources, source)
		for len(data) > 0 && !state.pesReady {
			need := 6
			if len(state.pesHeader) >= 6 {
				id := state.pesHeader[3]
				if id != 0xbc && id != 0xbe && id != 0xbf && id != 0xf0 && id != 0xf1 && id != 0xff && id != 0xf2 && id != 0xf8 {
					need = 9
					if len(state.pesHeader) >= 9 {
						need += int(state.pesHeader[8])
					}
				}
			}
			n := min(max(0, need-len(state.pesHeader)), len(data))
			state.pesHeader = append(state.pesHeader, data[:n]...)
			data = data[n:]
			source.Offset += n
			source.Length -= n
			if len(state.pesHeader) < need {
				return events
			}
			if len(state.pesHeader) == 6 && need == 6 {
				if !bytes.Equal(state.pesHeader[:3], []byte{0, 0, 1}) {
					state.pesStarted = false
					return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"start-code-missing"}, Sources: state.pesSources}}
				}
				id := state.pesHeader[3]
				if id != 0xbc && id != 0xbe && id != 0xbf && id != 0xf0 && id != 0xf1 && id != 0xff && id != 0xf2 && id != 0xf8 {
					continue
				}
			}
			if need == 9 && len(state.pesHeader) == 9 && state.pesHeader[8] != 0 {
				continue
			}
			fields := map[string]any{"StreamID": state.pesHeader[3], "DeclaredLength": binary.BigEndian.Uint16(state.pesHeader[4:]), "Codec": stream.Codec}
			if need >= 9 {
				if state.pesHeader[6]&0xc0 != 0x80 {
					state.pesStarted = false
					return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"MPEG1-or-invalid-PES-header"}, Sources: state.pesSources}}
				}
				flags := state.pesHeader[7] >> 6
				if flags == 1 {
					state.pesStarted = false
					return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"reserved-PTS-DTS-flags"}}}
				}
				if flags >= 2 {
					prefix := byte(2)
					if flags == 3 {
						prefix = 3
					}
					value, ok := pts(state.pesHeader[9:], prefix)
					if !ok {
						state.pesStarted = false
						return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"invalid-PTS"}}}
					}
					fields["PTS90kHz"] = value
				}
				if flags == 3 {
					if len(state.pesHeader) < 19 {
						state.pesStarted = false
						return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"short-DTS"}}}
					}
					value, ok := pts(state.pesHeader[14:], 1)
					if !ok {
						state.pesStarted = false
						return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"invalid-DTS"}}}
					}
					fields["DTS90kHz"] = value
				}
			}
			length := int(binary.BigEndian.Uint16(state.pesHeader[4:]))
			state.pesRemaining = -1
			if length > 0 {
				state.pesRemaining = length - (len(state.pesHeader) - 6)
				if state.pesRemaining < 0 {
					state.pesStarted = false
					return []Event{{Kind: "PES-rejected", PID: pid, Qualifications: []string{"declared-length-shorter-than-header"}}}
				}
			}
			events = append(events, Event{Kind: "PES-header", PID: pid, Fields: fields, Sources: state.pesSources})
			state.pesReady = true
		}
	}
	if state.pesRemaining >= 0 {
		n := min(len(data), state.pesRemaining)
		data = data[:n]
		state.pesRemaining -= n
	}
	if len(data) > 8192-len(state.es) || len(state.esSources) >= 128 {
		state.es = nil
		state.esSources = nil
		events = append(events, Event{Kind: "elementary-prefix-or-source-limit", PID: pid})
	}
	if len(data) > 0 {
		state.esSources = append(state.esSources, source)
	}
	state.es = append(state.es, data...)
	events = append(events, elementary(state, pid, stream, source)...)
	return events
}

func startCode(data []byte) (int, int) {
	for i := 0; i+2 < len(data); i++ {
		if data[i] == 0 && data[i+1] == 0 {
			if data[i+2] == 1 {
				return i, 3
			}
			if i+3 < len(data) && data[i+2] == 0 && data[i+3] == 1 {
				return i, 4
			}
		}
	}
	return -1, 0
}

func elementary(state *pidState, pid uint16, stream Stream, source Source) []Event {
	var events []Event
	if stream.Codec == "AAC-ADTS" {
		for len(state.es) >= 7 {
			d := state.es
			if d[0] != 0xff || d[1]&0xf6 != 0xf0 {
				state.es = state.es[1:]
				continue
			}
			index := d[2] >> 2 & 15
			if index > 12 {
				state.es = state.es[1:]
				continue
			}
			length := int(d[3]&3)<<11 | int(d[4])<<3 | int(d[5]>>5)
			header := 7
			if d[1]&1 == 0 {
				header = 9
			}
			if length < header || length > 8191 {
				state.es = state.es[1:]
				continue
			}
			if len(d) < length {
				break
			}
			events = append(events, Event{Kind: "AAC-ADTS", PID: pid, Fields: map[string]any{"SampleRate": []int{96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350}[index], "Channels": int(d[2]&1)<<2 | int(d[3]>>6), "ObjectType": (d[2] >> 6) + 1, "FrameLength": length, "Samples": 1024 * (int(d[6]&3) + 1)}, Sources: append([]Source(nil), state.esSources...)})
			state.es = state.es[length:]
		}
		if len(state.es) == 0 {
			state.esSources = nil
		}
		return events
	}
	for len(state.es) > 0 {
		index, prefix := startCode(state.es)
		if index < 0 {
			if len(state.es) > 3 {
				state.es = state.es[len(state.es)-3:]
				if len(state.esSources) > 1 {
					state.esSources = state.esSources[len(state.esSources)-1:]
				}
			}
			break
		}
		state.es = state.es[index:]
		data := state.es[prefix:]
		if len(data) < 4 {
			break
		}
		fields := map[string]any{"Codec": stream.Codec}
		consume := true
		switch stream.Codec {
		case "H264":
			kind := data[0] & 31
			fields["NALType"], fields["IDR"] = kind, kind == 5
			if kind == 7 {
				info, err := h264SPS(data[1:])
				if err == errBitsShort && len(state.es) < 4096 {
					consume = false
				} else if err == nil {
					fields["SPS"] = info
				} else {
					fields["SPSStatus"] = "invalid-or-unsupported"
				}
			}
		case "H265":
			kind := data[0] >> 1 & 63
			fields["NALType"], fields["IRAP"] = kind, kind >= 16 && kind <= 23
			if kind == 33 {
				info, err := h265SPS(data[2:])
				if err == errBitsShort && len(state.es) < 4096 {
					consume = false
				} else if err == nil {
					fields["SPS"] = info
				} else {
					fields["SPSStatus"] = "invalid-or-unsupported"
				}
			}
		case "MPEG-1-video", "MPEG-2-video":
			fields["StartCode"] = data[0]
			if data[0] == 0xb3 {
				if len(data) < 5 {
					consume = false
				} else {
					fields["Width"] = int(data[1])<<4 | int(data[2]>>4)
					fields["Height"] = int(data[2]&15)<<8 | int(data[3])
					fields["FrameRateCode"] = data[4] & 15
					fields["AspectRatioCode"] = data[4] >> 4
				}
			}
		default:
			if len(state.es) > 3 {
				state.es = state.es[len(state.es)-3:]
			}
			return events
		}
		if !consume {
			break
		}
		events = append(events, Event{Kind: "elementary-header", PID: pid, Fields: fields, Sources: append([]Source(nil), state.esSources...)})
		next, _ := startCode(data)
		if next >= 0 {
			state.es = data[next:]
		} else {
			if len(data) > 3 {
				state.es = data[len(data)-3:]
			} else {
				state.es = nil
			}
			if len(state.esSources) > 1 {
				state.esSources = state.esSources[len(state.esSources)-1:]
			}
			break
		}
	}
	return events
}
