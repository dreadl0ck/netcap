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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package zabbix

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/types"
)

type zabbixReader struct {
	conversation *core.ConversationInfo
}

// New returns a new Zabbix reader.
func (z *zabbixReader) New(conversation *core.ConversationInfo) core.StreamDecoderInterface {
	return &zabbixReader{
		conversation: conversation,
	}
}

const zabbixHeaderLen = 13 // 5 magic + 8 data length

// zabbixPayload represents the common fields in a Zabbix JSON payload.
type zabbixPayload struct {
	Request string `json:"request"`
	Host    string `json:"host"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}

// Decode parses Zabbix messages from the stream.
func (z *zabbixReader) Decode() {
	if Decoder.Writer == nil {
		zabbixLog.Error("Zabbix Decoder.Writer is nil")
		return
	}

	var regions [2]core.DataFragments
	var sizes [2]int
	flush := func(direction int) {
		data, index := core.Flatten(regions[direction])
		regions[direction] = nil
		sizes[direction] = 0
		for offset := 0; offset+zabbixHeaderLen <= len(data); {
			length, err := zabbixFrameLength(data[offset:])
			if err != nil {
				zabbixLog.Warn("invalid Zabbix frame", zap.Error(err))
				break
			}
			next := offset + length
			for _, rec := range z.parseZabbixMessages(data[offset:next]) {
				rec.SrcIP, rec.DstIP, rec.SrcPort, rec.DstPort = z.conversation.EndpointsAt(index, offset)
				rec.Flow = z.conversation.Ident
				rec.CommunityID = z.conversation.CommunityID
				rec.Timestamp, _ = index.At(offset)
				if err := Decoder.Writer.Write(rec); err != nil {
					zabbixLog.Error("failed to write zabbix record", zap.Error(err))
				} else {
					atomic.AddInt64(&Decoder.NumRecordsWritten, 1)
				}
			}
			offset = next
		}
	}
	for _, d := range z.conversation.Data {
		direction := 0
		if core.FromServer(d) {
			direction = 1
		}
		if stream, ok := d.(*core.StreamData); ok && stream.SkippedBytes != 0 {
			flush(direction)
		}
		if sizes[direction]+len(d.Raw()) > 16<<20 {
			flush(direction)
			continue
		}
		regions[direction] = append(regions[direction], d)
		sizes[direction] += len(d.Raw())
	}
	flush(0)
	flush(1)
}

func (z *zabbixReader) parseZabbixMessages(data []byte) []*types.Zabbix {
	var results []*types.Zabbix

	offset := 0
	for offset+zabbixHeaderLen <= len(data) {
		remaining := data[offset:]

		length, err := zabbixFrameLength(remaining)
		if err != nil {
			break
		}
		payload := remaining[zabbixHeaderLen:length]
		if remaining[4]&2 != 0 {
			r, err := zlib.NewReader(bytes.NewReader(payload))
			if err != nil {
				break
			}
			payload, err = io.ReadAll(io.LimitReader(r, maxZabbixPayload+1))
			closeErr := r.Close()
			if err != nil || closeErr != nil || len(payload) > maxZabbixPayload || uint32(len(payload)) != binary.LittleEndian.Uint32(remaining[9:13]) {
				break
			}
		}

		rec := &types.Zabbix{
			DataLength: int32(len(payload)),
		}

		// Parse JSON payload
		var zp zabbixPayload
		if err := json.Unmarshal(payload, &zp); err == nil {
			rec.RequestType = zp.Request
			rec.Host = zp.Host
			rec.Key = zp.Key
			rec.Value = zp.Value
		}

		results = append(results, rec)
		offset += length
	}

	return results
}

const maxZabbixPayload = 16 << 20

func zabbixFrameLength(data []byte) (int, error) {
	if len(data) < zabbixHeaderLen || !zabbixPrefix(data) {
		return 0, fmt.Errorf("unsupported or truncated Zabbix header")
	}
	length, expanded := binary.LittleEndian.Uint32(data[5:9]), binary.LittleEndian.Uint32(data[9:13])
	if length == 0 || length > maxZabbixPayload || uint64(length)+zabbixHeaderLen > uint64(len(data)) ||
		data[4] == 1 && expanded != 0 || data[4] == 3 && (expanded == 0 || expanded > maxZabbixPayload) {
		return 0, fmt.Errorf("invalid or over-limit Zabbix lengths")
	}
	return zabbixHeaderLen + int(length), nil
}
