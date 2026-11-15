package packet

import (
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket/layers"
)

func deviceFields(mac string) string { return "device/fields/" + storageKey(mac) + "/" }

func putDeviceFields(tx *aggregate.Tx, p *types.DeviceProfile) error {
	prefix := deviceFields(p.MacAddr)
	fields := map[string][]string{"ips": p.DeviceIPs, "services": p.AdvertisedServices, "devices": p.Devices, "names": p.Hostnames, "types": p.DeviceTypes, "roles": p.Roles}
	for field, values := range fields {
		for _, value := range values {
			if err := tx.Put(prefix+"sets/"+field+"/"+storageKey(value), []byte(value)); err != nil {
				return err
			}
			if field == "ips" {
				if err := tx.Put("device/ip/"+storageKey(value)+"/"+p.MacAddr, []byte(p.MacAddr)); err != nil {
					return err
				}
			}
		}
	}
	p.DeviceIPs, p.AdvertisedServices, p.Devices, p.Hostnames, p.DeviceTypes, p.Roles = nil, nil, nil, nil, nil, nil
	p.Contacts, p.Applications = nil, nil
	wire, err := proto.Marshal(p)
	if err != nil {
		return err
	}
	return tx.Put("device/base/"+p.MacAddr, wire)
}

func loadDeviceBase(tx *aggregate.Tx, mac string) (*deviceProfile, bool, error) {
	wire, found, err := tx.Get("device/base/" + mac)
	if err != nil || !found {
		return nil, found, err
	}
	p := &deviceProfile{DeviceProfile: &types.DeviceProfile{}, applications: map[string]struct{}{}}
	if err = proto.Unmarshal(wire, p.DeviceProfile); err != nil {
		return nil, false, err
	}
	return p, true, nil
}

func observeStoredContact(tx *aggregate.Tx, p *types.DeviceProfile, ip string) error {
	if ip == "" {
		return nil
	}
	p.ContactObservations++
	prefix := deviceFields(p.MacAddr) + "contacts/"
	_, seen, err := tx.Get(prefix + "seen/" + ip)
	if err != nil || seen {
		return err
	}
	if p.ContactCountLowerBound >= maxContactKeys {
		p.ContactCountLowerBound = maxContactKeys + 1
		p.ContactsTruncated = true
	} else {
		if err = tx.Put(prefix+"seen/"+ip, []byte{1}); err != nil {
			return err
		}
		p.ContactCountLowerBound++
	}
	_, sampled, err := tx.Get(prefix + "sample/" + ip)
	if err != nil || sampled {
		return err
	}
	count, _, err := storedCounter(tx, prefix+"count")
	if err != nil {
		return err
	}
	largest, _, err := tx.Get(prefix + "largest")
	if err != nil {
		return err
	}
	if count < maxReportedContacts {
		if err = tx.Put(prefix+"sample/"+ip, []byte(ip)); err != nil {
			return err
		}
		if err = putCounter(tx, prefix+"count", count+1); err != nil {
			return err
		}
		if ip > string(largest) {
			return tx.Put(prefix+"largest", []byte(ip))
		}
		return nil
	}
	p.ContactsTruncated = true
	if ip >= string(largest) {
		return nil
	}
	if err = tx.DeleteKey(prefix + "sample/" + string(largest)); err != nil {
		return err
	}
	if err = tx.Put(prefix+"sample/"+ip, []byte(ip)); err != nil {
		return err
	}
	_, largest, found, err := tx.Last(prefix + "sample/")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("device contact sample lost its largest member")
	}
	return tx.Put(prefix+"largest", largest)
}

func updateStoredDevice(i *decoderutils.PacketInfo) {
	var created int64
	err := conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
		p, found, err := loadDeviceBase(tx, i.SrcMAC)
		if err != nil {
			return err
		}
		if !found {
			created++
			p = newDeviceProfile(i)
			p.ContactObservations, p.ContactCountLowerBound = 0, 0
			p.ContactsTruncated = false
		} else {
			p.Timestamp = min(p.Timestamp, i.Timestamp)
			p.NumPackets++
			p.Bytes += uint64(len(i.Packet.Data()))
		}
		enrichDeviceProfileFromPacket(p, i.Packet)
		if err = observeStoredContact(tx, p.DeviceProfile, i.DstIP); err != nil {
			return err
		}
		if err = putDeviceFields(tx, p.DeviceProfile); err != nil {
			return err
		}
		if dpi.IsEnabled() {
			if err = bufferStoredDPI(tx, deviceFields(i.SrcMAC)+"dpi/", getStreamKey(i), i.Packet); err != nil {
				return err
			}
		}
		if layer := i.Packet.Layer(layers.LayerTypeDHCPv4); layer != nil {
			d := layer.(*layers.DHCPv4)
			mac := d.ClientHWAddr.String()
			if len(d.ClientHWAddr) == 6 && mac != "00:00:00:00:00:00" && mac != i.SrcMAC {
				target, found, err := loadDeviceBase(tx, mac)
				if err != nil {
					return err
				}
				if !found {
					created++
					target = &deviceProfile{DeviceProfile: &types.DeviceProfile{MacAddr: mac, Timestamp: i.Timestamp, DeviceManufacturer: resolvers.LookupManufacturer(mac)}}
				}
				target.Timestamp = min(target.Timestamp, i.Timestamp)
				enrichDHCPDeviceProfile(target, d)
				if err = putDeviceFields(tx, target.DeviceProfile); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err == nil {
		atomic.AddInt64(&deviceProfiles, created)
	}
}

func loadDeviceFields(tx *aggregate.Tx, p *types.DeviceProfile) (map[string]struct{}, error) {
	prefix := deviceFields(p.MacAddr)
	for field, target := range map[string]*[]string{"ips": &p.DeviceIPs, "services": &p.AdvertisedServices, "devices": &p.Devices, "names": &p.Hostnames, "types": &p.DeviceTypes, "roles": &p.Roles} {
		if err := tx.Each(prefix+"sets/"+field+"/", func(_ string, wire []byte) error { *target = append(*target, string(wire)); return nil }); err != nil {
			return nil, err
		}
	}
	if err := tx.Each(prefix+"contacts/sample/", func(_ string, wire []byte) error { p.Contacts = append(p.Contacts, string(wire)); return nil }); err != nil {
		return nil, err
	}
	apps := map[string]struct{}{}
	err := tx.Each(prefix+"applications/", func(_ string, wire []byte) error { apps[string(wire)] = struct{}{}; return nil })
	for app := range apps {
		p.Applications = append(p.Applications, app)
	}
	sort.Strings(p.Applications)
	return apps, err
}

func processStoredDeviceDPI(tx *aggregate.Tx, prefix string, clear bool) error {
	if err := tx.Each(prefix+"dpi/packets/", func(_ string, wire []byte) error {
		packet, err := unmarshalBufferedPacket(wire)
		if err != nil {
			return err
		}
		if len(packet.data) == 0 {
			return nil
		}
		for name := range dpi.GetProtocols(packet.packet()) {
			if err = tx.Put(prefix+"applications/"+storageKey(name), []byte(name)); err != nil {
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

func walkStoredDevices(processDPI, clear bool, fn func(*types.DeviceProfile, map[string]struct{}) error) error {
	last := ""
	for {
		var key string
		var p *types.DeviceProfile
		var apps map[string]struct{}
		err := conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
			var wire []byte
			var found bool
			var err error
			key, wire, found, err = tx.Next("device/base/", last)
			if err != nil || !found {
				return err
			}
			p = &types.DeviceProfile{}
			if err = proto.Unmarshal(wire, p); err != nil {
				return err
			}
			if processDPI {
				if err = processStoredDeviceDPI(tx, deviceFields(p.MacAddr), clear); err != nil {
					return err
				}
			}
			apps, err = loadDeviceFields(tx, p)
			return err
		})
		if err != nil {
			return err
		}
		if p == nil {
			return nil
		}
		if err = fn(p, apps); err != nil {
			return err
		}
		last = key
	}
}

func storedDeviceSnapshot(tx *aggregate.Tx, mac string) (*deviceProfile, error) {
	p, found, err := loadDeviceBase(tx, mac)
	if err != nil || !found {
		return nil, err
	}
	p.applications, err = loadDeviceFields(tx, p.DeviceProfile)
	if err != nil {
		return nil, err
	}
	p.storage = conf.AggregateStore
	p.storageGeneration = DeviceProfiles.generation
	return p, nil
}

func findStoredDevice(mac, ip string) *deviceProfile {
	var p *deviceProfile
	_ = conf.AggregateStore.Do(func(tx *aggregate.Tx) error {
		if ip != "" {
			prefix := "device/ip/" + storageKey(ip) + "/"
			first, wire, found, err := tx.Next(prefix, "")
			if err != nil || !found {
				return err
			}
			mac = string(wire)
			_, _, ambiguous, err := tx.Next(prefix, first)
			if err != nil || ambiguous {
				return err
			}
		}
		var err error
		p, err = storedDeviceSnapshot(tx, mac)
		return err
	})
	return p
}

func enrichStoredDevice(store *aggregate.Store, mac string, hostnames, deviceTypes, roles []string, os string) {
	_ = store.Do(func(tx *aggregate.Tx) error {
		p, found, err := loadDeviceBase(tx, mac)
		if err != nil || !found {
			return err
		}
		p.EnrichFromDiscovery(hostnames, deviceTypes, roles, os)
		return putDeviceFields(tx, p.DeviceProfile)
	})
}

// WalkDeviceProfiles supplies detached records without collecting every profile
// into a second in-memory snapshot. The callback must not re-enter profile APIs.
func WalkDeviceProfiles(visit func(*types.DeviceProfile) error) error {
	DeviceProfiles.operations.RLock()
	defer DeviceProfiles.operations.RUnlock()
	if conf != nil && conf.AggregateStore != nil {
		return walkStoredDevices(false, false, func(p *types.DeviceProfile, _ map[string]struct{}) error { return visit(p) })
	}
	DeviceProfiles.Lock()
	items := make([]*deviceProfile, 0, len(DeviceProfiles.Items))
	for _, p := range DeviceProfiles.Items {
		items = append(items, p)
	}
	DeviceProfiles.Unlock()
	for _, p := range items {
		p.Lock()
		copy := proto.Clone(p.DeviceProfile).(*types.DeviceProfile)
		p.Unlock()
		if err := visit(copy); err != nil {
			return err
		}
	}
	return nil
}
