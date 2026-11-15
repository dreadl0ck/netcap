package packet

import (
	"fmt"
	"net"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/dpi"
	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type deviceTestWriter struct {
	netio.AuditRecordWriter
	mu      sync.Mutex
	records []*types.DeviceProfile
}

func (w *deviceTestWriter) Write(record proto.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, proto.Clone(record).(*types.DeviceProfile))
	return nil
}

func deviceARP(t *testing.T, mac net.HardwareAddr, ip net.IP) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: mac, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: 1, SourceHwAddress: mac, SourceProtAddress: ip.To4(), DstHwAddress: make([]byte, 6), DstProtAddress: net.IPv4(10, 0, 0, 254).To4()}); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000001, 0), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return p
}

func deviceRelayedDHCP(t *testing.T, relay, client net.HardwareAddr, assigned net.IP) gopacket.Packet {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 3, 4, 254), DstIP: net.IPv4bcast}
	udp := &layers.UDP{SrcPort: 67, DstPort: 68}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: relay, DstMAC: net.HardwareAddr{255, 255, 255, 255, 255, 255}, EthernetType: layers.EthernetTypeIPv4}, ip, udp,
		&layers.DHCPv4{Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, YourClientIP: assigned, ClientHWAddr: client, Options: layers.DHCPOptions{{Type: layers.DHCPOptMessageType, Length: 1, Data: []byte{byte(layers.DHCPMsgTypeAck)}}, {Type: layers.DHCPOptHostname, Length: 10, Data: []byte("lease-host")}}}); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1700000002, 0), CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return p
}

func compareStoredDevices(t *testing.T, initDPI func()) {
	t.Helper()
	previous, previousInstance := conf, decoderconfig.Instance
	conf = &decoderconfig.Config{Quiet: true}
	decoderconfig.Instance = conf
	t.Cleanup(func() {
		conf.AggregateStore = nil
		ResetDeviceProfiles()
		conf, decoderconfig.Instance = previous, previousInstance
	})
	packets := connectionBenchmarkPackets(t, 100)
	for i, p := range packets {
		p.LinkLayer().(*layers.Ethernet).SrcMAC = net.HardwareAddr{2, 0, 0, 0, byte(i >> 8), byte(i + 1)}
		packets[i] = serializedEvidencePacket(t, p, p.Metadata().Timestamp)
	}
	firstMAC := packets[0].LinkLayer().(*layers.Ethernet).SrcMAC
	secondMAC := packets[1].LinkLayer().(*layers.Ethernet).SrcMAC
	ip := net.IPv4(10, 3, 4, 5)
	packets = append(packets, deviceARP(t, firstMAC, ip), deviceARP(t, secondMAC, ip))
	packets = append(packets, deviceRelayedDHCP(t, secondMAC, firstMAC, ip))
	relayOnlyClient := net.HardwareAddr{2, 0xaa, 0xbb, 0xcc, 0xdd, 1}
	relayOnlyIP := net.IPv4(10, 3, 4, 6)
	packets = append(packets, deviceRelayedDHCP(t, secondMAC, relayOnlyClient, relayOnlyIP))
	run := func(store *aggregate.Store) []*types.DeviceProfile {
		conf.AggregateStore = nil
		ResetDeviceProfiles()
		conf.AggregateStore = store
		initDPI()
		w := &deviceTestWriter{}
		d := &Decoder{Writer: w}
		for pass := 0; pass < 2; pass++ {
			for _, p := range packets {
				deviceProfileDecoder.Handler(p)
			}
			if DeviceProfiles.FindByIP(ip.String()) != nil {
				t.Fatal("ambiguous IP resolved to one MAC")
			}
			bound := DeviceProfiles.FindByIP(relayOnlyIP.String())
			if bound == nil || bound.MacAddr != relayOnlyClient.String() || bound.NumPackets != 0 || bound.Bytes != 0 {
				t.Fatal("DHCP-only client binding or traffic attribution lost", bound)
			}
			p := DeviceProfiles.FindByMAC(firstMAC.String())
			if p == nil {
				t.Fatal("known MAC missing")
			}
			p.EnrichFromDiscovery([]string{"host-a", ""}, []string{"Router"}, []string{"Workstation", "Master Browser"}, "fixture OS")
			if count := deviceProfileDecoder.FlushState(d); count != 101 {
				t.Fatalf("devices=%d, want 101", count)
			}
		}
		if err := deviceProfileDecoder.DeInit(d); err != nil {
			t.Fatal(err)
		}
		if DeviceProfiles.Size() != 101 {
			t.Fatal("wrong device count")
		}
		visited := 0
		if err := WalkDeviceProfiles(func(*types.DeviceProfile) error { visited++; return nil }); err != nil || visited != 101 {
			t.Fatal("profile walk lost devices", visited, err)
		}
		stale := DeviceProfiles.FindByMAC(firstMAC.String())
		ResetDeviceProfiles()
		deviceProfileDecoder.Handler(packets[0])
		stale.EnrichFromDiscovery([]string{"stale alias"}, nil, nil, "")
		fresh := DeviceProfiles.FindByMAC(firstMAC.String())
		if fresh == nil || slices.Contains(fresh.Hostnames, "stale alias") || DeviceProfiles.Size() != 1 {
			t.Fatal("reset snapshot mutated a later profile", fresh)
		}
		sort.SliceStable(w.records, func(i, j int) bool { return w.records[i].MacAddr < w.records[j].MacAddr })
		return w.records
	}
	want := run(nil)
	if dpi.IsEnabled() {
		classified := false
		for _, p := range want {
			if len(p.Applications) > 0 {
				classified = true
			}
		}
		if !classified {
			t.Fatal("device fixture did not exercise native DPI")
		}
	}
	for _, limit := range []int64{1, 2048, 1 << 20} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			store, err := aggregate.Open(t.TempDir(), limit, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			defer func() { conf.AggregateStore = nil }()
			got := run(store)
			if len(got) != len(want) {
				t.Fatalf("records=%d, want %d", len(got), len(want))
			}
			for i := range got {
				if !proto.Equal(got[i], want[i]) {
					t.Fatalf("device %d differs\ngot: %s\nwant: %s", i, got[i], want[i])
				}
			}
			if h := store.Health(); h.PeakBytes > limit || h.DiskWrites == 0 {
				t.Fatal(h)
			}
		})
	}
}

func TestStoredDevicesPreserveBindingDiscoveryAndReset(t *testing.T) {
	if dpi.IsEnabled() {
		t.Fatal("requires disabled DPI baseline")
	}
	compareStoredDevices(t, func() {})
}

func TestStoredDevicesPreserveNativeDPI(t *testing.T) {
	dpi.InitWithConfig("", dpi.RuntimeConfig{Workers: 1})
	defer dpi.Destroy()
	if !dpi.IsEnabled() {
		t.Skip("native DPI is not compiled in")
	}
	compareStoredDevices(t, func() { dpi.Destroy(); dpi.InitWithConfig("", dpi.RuntimeConfig{Workers: 1}) })
}

func TestStoredContactSamplingMatchesBoundedMemoryPolicy(t *testing.T) {
	store, err := aggregate.Open(t.TempDir(), 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var contacts []string
	for i := 1; i <= 67000; i++ {
		contacts = append(contacts, fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(contacts)))
	contacts = append(contacts, contacts[0], contacts[len(contacts)-1])
	want := &deviceProfile{DeviceProfile: &types.DeviceProfile{MacAddr: "02:00:00:00:00:01"}}
	got := &types.DeviceProfile{MacAddr: want.MacAddr}
	for _, ip := range contacts {
		observeContact(want, ip)
		if err = store.Do(func(tx *aggregate.Tx) error { return observeStoredContact(tx, got, ip) }); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.Do(func(tx *aggregate.Tx) error { _, err := loadDeviceFields(tx, got); return err }); err != nil {
		t.Fatal(err)
	}
	want.Contacts = append(want.Contacts[:0], want.contactHeap...)
	sort.Strings(want.Contacts)
	sort.Strings(got.Contacts)
	if !proto.Equal(got, want.DeviceProfile) {
		t.Fatalf("contact policy differs: observations %d/%d, lower bound %d/%d, samples %d/%d", got.ContactObservations, want.ContactObservations, got.ContactCountLowerBound, want.ContactCountLowerBound, len(got.Contacts), len(want.Contacts))
	}
	if h := store.Health(); h.PeakBytes > h.LimitBytes || h.Evictions == 0 {
		t.Fatal(h)
	}
}
