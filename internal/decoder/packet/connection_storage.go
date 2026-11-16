package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

type connectionDiskState struct {
	PacketsClient, PacketsServer                                              int64
	WindowSum, WindowSamples                                                  uint64
	StartedAt, EndedAt                                                        int64
	Generation                                                                uint64
	SYNTimestamp, SYNACKTimestamp, ClientHelloTimestamp, ServerHelloTimestamp int64
	SYNSequence                                                               uint32
	Flags, SYNTTL                                                             uint8
}

func marshalConnection(c *connection) ([]byte, error) {
	record := *c.Connection
	record.Applications = nil
	for app := range c.applications {
		record.Applications = append(record.Applications, app)
	}
	sort.Strings(record.Applications)
	wire, err := proto.Marshal(&record)
	if err != nil {
		return nil, err
	}
	var flags uint8
	for i, flag := range []bool{c.archived, c.tcpClosed, c.tcpSynSeen, c.finClient, c.finServer} {
		if flag {
			flags |= 1 << i
		}
	}
	state := connectionDiskState{c.packetsClientToServer, c.packetsServerToClient, c.windowSum, c.windowSamples, c.startedAt, c.endedAt, c.generation, c.synTimestamp, c.synAckTimestamp, c.clientHelloTimestamp, c.serverHelloTimestamp, c.tcpSynSequence, flags, c.synTTL}
	var buffer bytes.Buffer
	if err = binary.Write(&buffer, binary.LittleEndian, uint32(len(wire))); err != nil {
		return nil, err
	}
	buffer.Write(wire)
	if err = binary.Write(&buffer, binary.LittleEndian, state); err != nil {
		return nil, err
	}
	for _, text := range []string{c.clientIP, c.clientPort, c.sni} {
		if err = binary.Write(&buffer, binary.LittleEndian, uint32(len(text))); err != nil {
			return nil, err
		}
		buffer.WriteString(text)
	}
	return buffer.Bytes(), nil
}

func unmarshalConnection(data []byte) (*connection, error) {
	reader := bytes.NewReader(data)
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	if uint64(length) > uint64(reader.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	var record types.Connection
	if err := proto.Unmarshal(data[4:4+int(length)], &record); err != nil {
		return nil, err
	}
	if _, err := reader.Seek(int64(length), io.SeekCurrent); err != nil {
		return nil, err
	}
	var state connectionDiskState
	if err := binary.Read(reader, binary.LittleEndian, &state); err != nil {
		return nil, err
	}
	var texts [3]string
	for i := range texts {
		if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
			return nil, err
		}
		if uint64(length) > uint64(reader.Len()) {
			return nil, io.ErrUnexpectedEOF
		}
		raw := make([]byte, int(length))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return nil, err
		}
		texts[i] = string(raw)
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("trailing connection state bytes")
	}
	c := &connection{Connection: &record, clientIP: texts[0], clientPort: texts[1], sni: texts[2], packetsClientToServer: state.PacketsClient, packetsServerToClient: state.PacketsServer, windowSum: state.WindowSum, windowSamples: state.WindowSamples, startedAt: state.StartedAt, endedAt: state.EndedAt, generation: state.Generation, synTimestamp: state.SYNTimestamp, synAckTimestamp: state.SYNACKTimestamp, clientHelloTimestamp: state.ClientHelloTimestamp, serverHelloTimestamp: state.ServerHelloTimestamp, tcpSynSequence: state.SYNSequence, synTTL: state.SYNTTL, archived: state.Flags&1 != 0, tcpClosed: state.Flags&2 != 0, tcpSynSeen: state.Flags&4 != 0, finClient: state.Flags&8 != 0, finServer: state.Flags&16 != 0}
	if len(record.Applications) > 0 {
		c.applications = make(map[string]struct{}, len(record.Applications))
		for _, app := range record.Applications {
			c.applications[app] = struct{}{}
		}
	}
	record.Applications = nil
	return c, nil
}

func connectionHistoryPrefix(key string) string {
	return "connection/history/" + base64.RawURLEncoding.EncodeToString([]byte(key)) + "/"
}

func connectionHistoryKey(prefix string, started int64, generation uint64) string {
	return fmt.Sprintf("%s%016x/%016x", prefix, uint64(started)^(uint64(1)<<63), generation)
}

func putStoredConnection(tx *aggregate.Tx, key string, c *connection) error {
	wire, err := marshalConnection(c)
	if err != nil {
		return err
	}
	return tx.Put(key, wire)
}

func handleStoredConnection(p gopacket.Packet, id connectionID, ll gopacket.LinkLayer, nl gopacket.NetworkLayer, tl gopacket.TransportLayer) {
	_ = conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
		base := id.String()
		key := "connection/current/" + base64.RawURLEncoding.EncodeToString([]byte(base))
		wire, found, err := tx.Get(key)
		if err != nil {
			return err
		}
		if !found {
			return putStoredConnection(tx, key, makeConnection(p, id, ll, nl, tl, 0))
		}
		c, err := unmarshalConnection(wire)
		if err != nil {
			return err
		}
		prefix := connectionHistoryPrefix(base)
		at := p.Metadata().Timestamp.UnixNano()
		if at < c.startedAt {
			var historyKey string
			historyKey, wire, found, err = tx.Find(prefix, connectionHistoryKey(prefix, at, ^uint64(0)), true)
			if err != nil {
				return err
			}
			if !found {
				historyKey, wire, found, err = tx.Find(prefix, "", false)
				if err != nil {
					return err
				}
			}
			if found {
				key = historyKey
				c, err = unmarshalConnection(wire)
				if err != nil {
					return err
				}
			}
		}
		if !c.archived && connectionNewSYN(c, p) {
			c.archived, c.endedAt = true, at
			if err := putStoredConnection(tx, connectionHistoryKey(prefix, c.startedAt, c.generation), c); err != nil {
				return err
			}
			return putStoredConnection(tx, key, makeConnection(p, id, ll, nl, tl, c.generation+1))
		}
		updateConnection(c, p, ll, nl, tl)
		return putStoredConnection(tx, key, c)
	})
}

func flushStoredConnections(d *Decoder) (int64, error) {
	var count int64
	err := conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
		return tx.EachStable("connection/", func(key string, wire []byte) error {
			c, err := unmarshalConnection(wire)
			if err != nil {
				return err
			}
			writeConnectionRecord(d, c)
			count++
			return putStoredConnection(tx, key, c)
		})
	})
	return count, err
}
