package packet

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	"github.com/dreadl0ck/netcap/internal/packetmeta"
	"github.com/gopacket/gopacket"
)

type storedDPIPacket struct {
	Data    []byte
	Base    int
	Capture packetmeta.Capture
}

func marshalBufferedPacket(p bufferedPacket) ([]byte, error) {
	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(storedDPIPacket{Data: p.data, Base: int(p.base), Capture: packetmeta.Save(p.info)})
	return buffer.Bytes(), err
}

func unmarshalBufferedPacket(wire []byte) (bufferedPacket, error) {
	var saved storedDPIPacket
	reader := bytes.NewReader(wire)
	if err := gob.NewDecoder(reader).Decode(&saved); err != nil {
		return bufferedPacket{}, err
	}
	if reader.Len() != 0 {
		return bufferedPacket{}, fmt.Errorf("trailing deferred packet state")
	}
	return bufferedPacket{data: saved.Data, base: gopacket.LayerType(saved.Base), info: saved.Capture.Restore()}, nil
}

func storageKey(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }

func base64DecodeStorageKey(text string) (string, error) {
	wire, err := base64.RawURLEncoding.DecodeString(text)
	return string(wire), err
}

func streamStorageKey(k streamKey) string {
	// Separate encoded components cannot collide on delimiters inside an address.
	return storageKey(k.srcIP) + "." + storageKey(k.dstIP) + "." + storageKey(k.srcPort) + "." + storageKey(k.dstPort) + "." + storageKey(k.protocol)
}

func storedCounter(tx *aggregate.Tx, key string) (uint64, bool, error) {
	wire, found, err := tx.Get(key)
	if err != nil || !found {
		return 0, found, err
	}
	if len(wire) != 8 {
		return 0, false, fmt.Errorf("invalid aggregate counter length %d", len(wire))
	}
	return binary.LittleEndian.Uint64(wire), true, nil
}

func putCounter(tx *aggregate.Tx, key string, value uint64) error {
	return tx.Put(key, binary.LittleEndian.AppendUint64(nil, value))
}

func bufferStoredDPI(tx *aggregate.Tx, prefix string, k streamKey, p gopacket.Packet) error {
	streamKey := prefix + "streams/" + streamStorageKey(k)
	count, exists, err := storedCounter(tx, streamKey)
	if err != nil {
		return err
	}
	if count >= maxPacketsPerStream {
		return nil
	}
	if !exists {
		streams, _, err := storedCounter(tx, prefix+"count")
		if err != nil {
			return err
		}
		if streams >= maxStreamsPerProfile {
			return nil
		}
		if err = putCounter(tx, prefix+"count", streams+1); err != nil {
			return err
		}
	}
	wire, err := marshalBufferedPacket(bufferDPIPacket(p))
	if err != nil {
		return err
	}
	if err = tx.Put(fmt.Sprintf("%spackets/%s/%02d", prefix, streamStorageKey(k), count), wire); err != nil {
		return err
	}
	return putCounter(tx, streamKey, count+1)
}
