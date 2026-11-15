package packet

import (
	"encoding/binary"
	"fmt"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

func putHostPort(tx *aggregate.Tx, prefix, kind, protocol string, port int32, nbytes uint64) error {
	key := fmt.Sprintf("%sports/%s/%s/%05d", prefix, kind, storageKey(protocol), port)
	wire, found, err := tx.Get(key)
	if err != nil {
		return err
	}
	var record types.Port
	if found {
		if err = proto.Unmarshal(wire, &record); err != nil {
			return err
		}
	} else {
		record = types.Port{PortNumber: port, Protocol: protocol, Stats: &types.PortStats{}}
	}
	if record.Stats == nil {
		return fmt.Errorf("stored host port has no counters")
	}
	record.Stats.Packets++
	record.Stats.Bytes += nbytes
	wire, err = proto.Marshal(&record)
	if err != nil {
		return err
	}
	return tx.Put(key, wire)
}

func putHostProperties(tx *aggregate.Tx, prefix string, host *types.Host) error {
	for name, values := range map[string][]string{"devices": host.Devices, "ja4": host.Ja4Fingerprints, "ja4s": host.Ja4SFingerprints} {
		for _, value := range values {
			if err := tx.Put(prefix+"sets/"+name+"/"+storageKey(value), []byte(value)); err != nil {
				return err
			}
		}
	}
	for name, count := range host.SNIs {
		key := prefix + "sni/" + storageKey(name)
		old, _, err := storedCounter(tx, key)
		if err != nil {
			return err
		}
		if err = putCounter(tx, key, old+uint64(count)); err != nil {
			return err
		}
	}
	host.Devices, host.Ja4Fingerprints, host.Ja4SFingerprints = nil, nil, nil
	host.SNIs = nil
	host.SrcPorts, host.DstPorts, host.ContactedPorts = nil, nil, nil
	return nil
}

func updateStoredHost(addr string, i *decoderutils.PacketInfo, source bool) {
	_ = conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
		encoded := storageKey(addr)
		key := "host/base/" + addr
		prefix := "host/fields/" + encoded + "/"
		wire, found, err := tx.Get(key)
		if err != nil {
			return err
		}
		var host *hostEntry
		if found {
			host = &hostEntry{Host: &types.Host{}}
			if err = proto.Unmarshal(wire, host.Host); err != nil {
				return err
			}
			host.NumPackets++
			host.TimestampFirst = min(host.TimestampFirst, i.Timestamp)
			host.TimestampLast = max(host.TimestampLast, i.Timestamp)
			host.Bytes += uint64(len(i.Packet.Data()))
			handleTLSFingerprinting(host, i)
			handleDHCPFingerprinting(host, i)
		} else {
			host = createNewHost(addr, i, source)
		}
		if tl := i.Packet.TransportLayer(); tl != nil {
			flow := tl.TransportFlow()
			src, dst := utils.DecodePort(flow.Src().Raw()), utils.DecodePort(flow.Dst().Raw())
			protocol := tl.LayerType().String()
			own, contacted := src, dst
			kind := "src"
			if !source {
				own, contacted, kind = dst, src, "dst"
			}
			if err = putHostPort(tx, prefix, kind, protocol, own, uint64(len(i.Packet.Data()))); err != nil {
				return err
			}
			if err = putHostPort(tx, prefix, "contacted", protocol, contacted, uint64(len(i.Packet.Data()))); err != nil {
				return err
			}
		}
		if err = putHostProperties(tx, prefix, host.Host); err != nil {
			return err
		}
		wire, err = proto.Marshal(host.Host)
		if err != nil {
			return err
		}
		if err = tx.Put(key, wire); err != nil {
			return err
		}
		if dpi.IsEnabled() {
			return bufferStoredDPI(tx, prefix+"dpi/", getStreamKey(i), i.Packet)
		}
		return nil
	})
}

func processStoredHostDPI(tx *aggregate.Tx, prefix string, clear bool) error {
	if err := tx.Each(prefix+"dpi/packets/", func(_ string, wire []byte) error {
		packet, err := unmarshalBufferedPacket(wire)
		if err != nil {
			return err
		}
		if len(packet.data) == 0 {
			return nil
		}
		for name, result := range dpi.GetProtocols(packet.packet()) {
			key := prefix + "protocols/" + storageKey(name)
			wire, found, err := tx.Get(key)
			if err != nil {
				return err
			}
			var record *types.Protocol
			if found {
				record = &types.Protocol{}
				if err = proto.Unmarshal(wire, record); err != nil {
					return err
				}
				record.Packets++
			} else {
				record = dpi.NewProto(&result)
			}
			wire, err = proto.Marshal(record)
			if err != nil {
				return err
			}
			if err = tx.Put(key, wire); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if clear {
		return tx.Delete(prefix + "dpi/")
	}
	return nil
}

func loadHostFields(tx *aggregate.Tx, prefix string, host *types.Host) error {
	for name, target := range map[string]*[]*types.Port{"src": &host.SrcPorts, "dst": &host.DstPorts, "contacted": &host.ContactedPorts} {
		if err := tx.Each(prefix+"ports/"+name+"/", func(_ string, wire []byte) error {
			port := &types.Port{}
			if err := proto.Unmarshal(wire, port); err != nil {
				return err
			}
			*target = append(*target, port)
			return nil
		}); err != nil {
			return err
		}
	}
	for name, target := range map[string]*[]string{"devices": &host.Devices, "ja4": &host.Ja4Fingerprints, "ja4s": &host.Ja4SFingerprints} {
		if err := tx.Each(prefix+"sets/"+name+"/", func(_ string, wire []byte) error { *target = append(*target, string(wire)); return nil }); err != nil {
			return err
		}
	}
	if err := tx.Each(prefix+"sni/", func(key string, wire []byte) error {
		if len(wire) != 8 {
			return fmt.Errorf("invalid stored SNI count")
		}
		name, err := base64DecodeStorageKey(key[len(prefix+"sni/"):])
		if err != nil {
			return err
		}
		if host.SNIs == nil {
			host.SNIs = map[string]int64{}
		}
		host.SNIs[name] = int64(binary.LittleEndian.Uint64(wire))
		return nil
	}); err != nil {
		return err
	}
	return tx.Each(prefix+"protocols/", func(key string, wire []byte) error {
		name, err := base64DecodeStorageKey(key[len(prefix+"protocols/"):])
		if err != nil {
			return err
		}
		record := &types.Protocol{}
		if err = proto.Unmarshal(wire, record); err != nil {
			return err
		}
		if host.Protocols == nil {
			host.Protocols = map[string]*types.Protocol{}
		}
		host.Protocols[name] = record
		return nil
	})
}

func flushStoredHosts(d *Decoder, clear bool) (int64, error) {
	var count int64
	last := ""
	for {
		var key string
		var host *types.Host
		err := conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
			var wire []byte
			var found bool
			var err error
			key, wire, found, err = tx.Next("host/base/", last)
			if err != nil || !found {
				return err
			}
			host = &types.Host{}
			if err = proto.Unmarshal(wire, host); err != nil {
				return err
			}
			prefix := "host/fields/" + storageKey(key[len("host/base/"):]) + "/"
			if err = processStoredHostDPI(tx, prefix, clear); err != nil {
				return err
			}
			return loadHostFields(tx, prefix, host)
		})
		if err != nil {
			return count, err
		}
		if host == nil {
			return count, nil
		}
		d.writeHost(host)
		count++
		last = key
	}
}
