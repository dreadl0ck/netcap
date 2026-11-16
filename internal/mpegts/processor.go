package mpegts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const pidCredit = 32768
const scopeCredit = 65536

type Source struct {
	Ordinal        uint64
	Offset, Length int
	ChildOrdinal   uint32 `json:",omitempty"`
	Derived        bool   `json:",omitempty"`
}
type Event struct {
	Kind           string
	PID            uint16
	Scope          string   `json:",omitempty"`
	Fields         any      `json:",omitempty"`
	Qualifications []string `json:",omitempty"`
	Sources        []Source `json:",omitempty"`
}
type Program struct{ Number, PMTPID uint16 }
type Stream struct {
	PID             uint16
	Type            byte
	Codec, Language string
}
type scopeState struct {
	programs       map[uint16]uint16
	streams        map[uint16]Stream
	programStreams map[uint16][]Stream
	sections       map[byte][]Program
	patVersion     byte
	patID          uint16
	lastSection    byte
	activeID       uint16
	activePAT      bool
	generation     uint64
	ordinal        uint64
}
type pidState struct {
	pid            uint16
	scope          string
	cc             byte
	haveCC         bool
	last           []byte
	section        []byte
	sectionSources []Source
	pesHeader      []byte
	pesReady       bool
	pesStarted     bool
	pesRemaining   int
	pesSources     []Source
	es             []byte
	esSources      []Source
	codec          string
	generation     uint64
	ordinal        uint64
}
type Processor struct {
	Reserve func(int) bool
	Release func(int)
	scopes  map[string]*scopeState
	pids    map[string]*pidState
	credit  int
}

func (p *Processor) reserve(n int) bool {
	if p.credit+n > 8<<20 || p.Reserve != nil && !p.Reserve(n) {
		return false
	}
	p.credit += n
	return true
}
func (p *Processor) release(n int) {
	p.credit -= n
	if p.Release != nil {
		p.Release(n)
	}
}
func (p *Processor) Reset() {
	if p.credit > 0 {
		p.release(p.credit)
	}
	p.scopes = nil
	p.pids = nil
}
func (p *Processor) Incomplete() []Event {
	var events []Event
	keys := make([]string, 0, len(p.pids))
	for key := range p.pids {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		state := p.pids[key]
		if len(state.section) > 0 {
			events = append(events, Event{Kind: "PSI-incomplete", PID: state.pid, Scope: state.scope, Sources: state.sectionSources, Qualifications: []string{"capture-end"}})
		}
		if state.pesStarted && (!state.pesReady || state.pesRemaining > 0) {
			events = append(events, Event{Kind: "PES-incomplete", PID: state.pid, Scope: state.scope, Sources: state.pesSources, Qualifications: []string{"capture-end"}})
		}
	}
	return events
}
func resetPID(state *pidState) {
	state.section = nil
	state.sectionSources = nil
	state.pesHeader = nil
	state.pesReady = false
	state.pesStarted = false
	state.es = nil
	state.esSources = nil
	state.pesSources = nil
}
func (p *Processor) Expire(ordinal uint64) {
	for key, state := range p.pids {
		if ordinal >= state.ordinal && ordinal-state.ordinal > 65536 {
			delete(p.pids, key)
			p.release(pidCredit)
		}
	}
	for key, state := range p.scopes {
		if ordinal >= state.ordinal && ordinal-state.ordinal > 65536 {
			delete(p.scopes, key)
			p.release(scopeCredit)
		}
	}
}

func (p *Processor) Push(scope string, wire []byte, source Source) ([]Event, error) {
	if len(wire) != 188 || wire[0] != 0x47 {
		return nil, fmt.Errorf("invalid MPEG-TS frame")
	}
	pid := binary.BigEndian.Uint16(wire[1:3]) & 0x1fff
	event := func(reason string) []Event {
		return []Event{{Kind: "MPEG-TS-incomplete", PID: pid, Qualifications: []string{reason}, Sources: []Source{source}}}
	}
	if wire[1]&0x80 != 0 || wire[3]>>6 != 0 {
		if state := p.pids[fmt.Sprintf("%s/%d", scope, pid)]; state != nil {
			resetPID(state)
			state.haveCC = false
		}
		if wire[1]&0x80 != 0 {
			return event("transport-error-indicator"), nil
		}
		return event("scrambled-payload-not-decoded"), nil
	}
	control := wire[3] >> 4 & 3
	if control == 0 {
		return event("reserved-adaptation-control"), nil
	}
	offset := 4
	discontinuity := false
	if control&2 != 0 {
		n := int(wire[4])
		if n > 183 {
			return event("adaptation-length-exceeds-frame"), nil
		}
		if n > 0 {
			discontinuity = wire[5]&0x80 != 0
		}
		offset += 1 + n
	}
	if control&1 == 0 || offset == 188 || pid == 0x1fff {
		return nil, nil
	}
	p.Expire(source.Ordinal)
	if p.scopes == nil {
		p.scopes = map[string]*scopeState{}
		p.pids = map[string]*pidState{}
	}
	state := p.scopes[scope]
	if state == nil {
		if len(p.scopes) >= 64 || !p.reserve(scopeCredit) {
			return nil, fmt.Errorf("MPEG-TS scope/state budget exceeded")
		}
		state = &scopeState{programs: map[uint16]uint16{}, streams: map[uint16]Stream{}, programStreams: map[uint16][]Stream{}, sections: map[byte][]Program{}}
		p.scopes[scope] = state
	}
	state.ordinal = source.Ordinal
	psi := pid == 0
	for _, pmt := range state.programs {
		if pmt == pid {
			psi = true
			break
		}
	}
	stream, knownStream := state.streams[pid]
	if !psi && !knownStream {
		return nil, nil
	}
	key := fmt.Sprintf("%s/%d", scope, pid)
	entry := p.pids[key]
	if entry == nil {
		if len(p.pids) >= 256 || !p.reserve(pidCredit) {
			return nil, fmt.Errorf("MPEG-TS PID/state budget exceeded")
		}
		entry = &pidState{pid: pid, scope: scope}
		p.pids[key] = entry
	}
	entry.ordinal = source.Ordinal
	if !psi && (entry.codec != stream.Codec || entry.generation != state.generation) {
		entry.codec = stream.Codec
		entry.generation = state.generation
		resetPID(entry)
	}
	cc := wire[3] & 15
	if entry.haveCC && cc == entry.cc && bytes.Equal(wire, entry.last) && !discontinuity {
		return nil, nil
	}
	var events []Event
	if discontinuity || entry.haveCC && cc != (entry.cc+1)&15 {
		events = append(events, event("continuity-discontinuity")...)
		resetPID(entry)
	}
	entry.haveCC, entry.cc = true, cc
	entry.last = append(entry.last[:0], wire...)
	payload := wire[offset:]
	start := wire[1]&0x40 != 0
	source.Offset += offset
	source.Length = len(payload)
	if psi {
		if start {
			pointer := int(payload[0])
			payload = payload[1:]
			source.Offset++
			source.Length--
			if pointer > len(payload) {
				return append(events, event("PSI-pointer-exceeds-payload")...), nil
			}
			if len(entry.section) > 0 {
				p.sections(state, entry, pid, payload[:pointer], source, false, &events)
				if len(entry.section) > 0 {
					events = append(events, event("PSI-start-before-section-complete")...)
					entry.section = nil
					entry.sectionSources = nil
				}
			}
			payload = payload[pointer:]
			source.Offset += pointer
			source.Length = len(payload)
			p.sections(state, entry, pid, payload, source, true, &events)
		} else if len(entry.section) > 0 {
			p.sections(state, entry, pid, payload, source, false, &events)
		}
	} else {
		events = append(events, pes(entry, pid, stream, payload, start, source)...)
	}
	return events, nil
}

func (p *Processor) sections(scope *scopeState, state *pidState, pid uint16, data []byte, source Source, newSections bool, events *[]Event) {
	for len(data) > 0 {
		if len(state.section) == 0 {
			if !newSections || data[0] == 0xff {
				return
			}
			state.sectionSources = nil
		}
		n := 3 - len(state.section)
		if n <= 0 {
			n = 3 + int(binary.BigEndian.Uint16(state.section[1:])&0xfff) - len(state.section)
		}
		if n < 0 || n > 4096 {
			state.section = nil
			state.sectionSources = nil
			*events = append(*events, Event{Kind: "PSI-rejected", PID: pid, Qualifications: []string{"section-length-limit"}})
			return
		}
		n = min(n, len(data))
		state.section = append(state.section, data[:n]...)
		if n > 0 {
			if len(state.sectionSources) >= 128 {
				state.section = nil
				state.sectionSources = nil
				*events = append(*events, Event{Kind: "PSI-rejected", PID: pid, Qualifications: []string{"section-source-limit"}})
				return
			}
			part := source
			part.Length = n
			state.sectionSources = append(state.sectionSources, part)
			source.Offset += n
			source.Length -= n
			data = data[n:]
		}
		if len(state.section) < 3 {
			return
		}
		length := 3 + int(binary.BigEndian.Uint16(state.section[1:])&0xfff)
		if length < 12 || length > 1024 {
			state.section = nil
			state.sectionSources = nil
			*events = append(*events, Event{Kind: "PSI-rejected", PID: pid, Qualifications: []string{"PAT-PMT-length-outside-bounds"}})
			return
		}
		if len(state.section) < length {
			continue
		}
		event := parseSection(scope, pid, state.section)
		event.Sources = state.sectionSources
		*events = append(*events, event)
		state.section = nil
		state.sectionSources = nil
		if !newSections {
			return
		}
	}
}

func CRC(data []byte) uint32 {
	crc := uint32(0xffffffff)
	for _, value := range data {
		crc ^= uint32(value) << 24
		for range 8 {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04c11db7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func parseSection(scope *scopeState, pid uint16, data []byte) Event {
	e := Event{PID: pid, Kind: "PSI"}
	if data[1]&0x80 == 0 || CRC(data) != 0 {
		e.Qualifications = []string{"invalid-PSI-syntax-or-CRC32"}
		return e
	}
	if data[5]&1 == 0 {
		e.Qualifications = []string{"next-table-not-active"}
		return e
	}
	switch data[0] {
	case 0:
		e.Kind = "PAT"
		version := data[5] >> 1 & 31
		id := binary.BigEndian.Uint16(data[3:])
		section, last := data[6], data[7]
		if pid != 0 || section > last || last > 63 || (len(data)-12)%4 != 0 {
			e.Qualifications = []string{"invalid-or-unsupported-PAT-section-layout"}
			return e
		}
		var programs []Program
		for offset := 8; offset < len(data)-4; offset += 4 {
			number := binary.BigEndian.Uint16(data[offset:])
			if number != 0 {
				programs = append(programs, Program{number, binary.BigEndian.Uint16(data[offset+2:]) & 0x1fff})
			}
		}
		if scope.patVersion != version || scope.patID != id || scope.lastSection != last {
			scope.sections = map[byte][]Program{}
			scope.patVersion, scope.patID, scope.lastSection = version, id, last
		}
		total := len(programs)
		for index, entries := range scope.sections {
			if index != section {
				total += len(entries)
			}
		}
		if total > 1024 {
			e.Qualifications = []string{"PAT-program-limit"}
			return e
		}
		scope.sections[section] = programs
		e.Fields = map[string]any{"Version": version, "Section": section, "LastSection": last, "Programs": programs}
		if len(scope.sections) == int(last)+1 {
			active := map[uint16]uint16{}
			for i := 0; i <= int(last); i++ {
				for _, program := range scope.sections[byte(i)] {
					active[program.Number] = program.PMTPID
				}
			}
			changed := !scope.activePAT || scope.activeID != id || len(active) != len(scope.programs)
			for program, target := range active {
				if prior, ok := scope.programs[program]; !ok || prior != target {
					changed = true
				}
			}
			for program := range scope.programStreams {
				target, ok := active[program]
				if !ok || !scope.activePAT || scope.activeID != id || scope.programs[program] != target {
					delete(scope.programStreams, program)
				}
			}
			scope.programs = active
			scope.activeID = id
			scope.activePAT = true
			if changed {
				scope.generation++
			}
			rebuildStreams(scope)
		}
	case 2:
		e.Kind = "PMT"
		if len(data) < 16 || data[6] != 0 || data[7] != 0 {
			e.Qualifications = []string{"invalid-or-unsupported-PMT-section-layout"}
			return e
		}
		program := binary.BigEndian.Uint16(data[3:])
		expected, ok := scope.programs[program]
		if !ok || expected != pid {
			e.Qualifications = []string{"PMT-not-in-active-PAT"}
			return e
		}
		pcr := binary.BigEndian.Uint16(data[8:]) & 0x1fff
		offset := 12 + int(binary.BigEndian.Uint16(data[10:])&0xfff)
		if offset > len(data)-4 {
			e.Qualifications = []string{"PMT-program-descriptors-exceed-section"}
			return e
		}
		var streams []Stream
		for offset < len(data)-4 {
			if len(data)-4-offset < 5 {
				e.Qualifications = []string{"short-PMT-stream"}
				return e
			}
			stream := Stream{PID: binary.BigEndian.Uint16(data[offset+1:]) & 0x1fff, Type: data[offset]}
			stream.Codec = codec(stream.Type)
			n := int(binary.BigEndian.Uint16(data[offset+3:]) & 0xfff)
			offset += 5
			if n > len(data)-4-offset {
				e.Qualifications = []string{"PMT-stream-descriptors-exceed-section"}
				return e
			}
			for d := 0; d < n; {
				if n-d < 2 || int(data[offset+d+1]) > n-d-2 {
					e.Qualifications = []string{"invalid-PMT-descriptor"}
					return e
				}
				size := int(data[offset+d+1])
				if data[offset+d] == 10 && size >= 4 {
					lang := data[offset+d+2 : offset+d+5]
					valid := true
					for _, b := range lang {
						if b < 'a' || b > 'z' {
							valid = false
						}
					}
					if valid {
						stream.Language = string(lang)
					}
				}
				d += 2 + size
			}
			offset += n
			streams = append(streams, stream)
		}
		total := len(streams)
		for owner, list := range scope.programStreams {
			if owner != program {
				total += len(list)
			}
		}
		if total > 512 {
			e.Qualifications = []string{"PMT-stream-limit"}
			return e
		}
		scope.programStreams[program] = streams
		rebuildStreams(scope)
		e.Fields = map[string]any{"Program": program, "Version": data[5] >> 1 & 31, "PCRPID": pcr, "Streams": streams}
	default:
		e.Qualifications = []string{"PSI-table-not-decoded"}
	}
	return e
}

func rebuildStreams(scope *scopeState) {
	previous := scope.streams
	scope.streams = map[uint16]Stream{}
	programs := make([]int, 0, len(scope.programStreams))
	for program := range scope.programStreams {
		programs = append(programs, int(program))
	}
	sort.Ints(programs)
	for _, program := range programs {
		for _, stream := range scope.programStreams[uint16(program)] {
			if prior, exists := scope.streams[stream.PID]; exists && (prior.Type != stream.Type || prior.Codec != stream.Codec) {
				stream.Codec = "ambiguous-PMT-codec"
			}
			scope.streams[stream.PID] = stream
		}
	}
	changed := len(previous) != len(scope.streams)
	for pid, stream := range scope.streams {
		if prior, ok := previous[pid]; !ok || prior != stream {
			changed = true
		}
	}
	if changed {
		scope.generation++
	}
}

func codec(kind byte) string {
	return map[byte]string{1: "MPEG-1-video", 2: "MPEG-2-video", 3: "MPEG-1-audio", 4: "MPEG-2-audio", 0x0f: "AAC-ADTS", 0x11: "AAC-LATM", 0x1b: "H264", 0x24: "H265", 0x81: "AC3"}[kind]
}
