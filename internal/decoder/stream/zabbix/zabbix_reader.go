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
	"encoding/binary"
	"encoding/json"
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
			if !bytes.Equal(data[offset:offset+5], zabbixMagic) {
				break
			}
			length := binary.LittleEndian.Uint64(data[offset+5 : offset+13])
			if length == 0 || length > uint64(len(data)-offset-zabbixHeaderLen) {
				break
			}
			next := offset + zabbixHeaderLen + int(length)
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

		// Look for ZBXD\x01 magic
		if !bytes.Equal(remaining[:5], zabbixMagic) {
			// Try to find the next magic header
			idx := bytes.Index(remaining[1:], zabbixMagic)
			if idx < 0 {
				break
			}
			offset += 1 + idx
			continue
		}

		// Data length is 8 bytes, little-endian int64
		dataLen := int64(binary.LittleEndian.Uint64(remaining[5:13]))
		if dataLen <= 0 || int64(offset)+int64(zabbixHeaderLen)+dataLen > int64(len(data)) {
			break
		}

		payload := remaining[zabbixHeaderLen : zabbixHeaderLen+int(dataLen)]

		rec := &types.Zabbix{
			DataLength: int32(dataLen),
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
		offset += zabbixHeaderLen + int(dataLen)
	}

	return results
}
