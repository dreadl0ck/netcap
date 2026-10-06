// Package behavior maintains scoped, passive observations and approved baselines.
package behavior

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const SchemaVersion = 3

type Mode string

const (
	Learning   Mode = "learning"
	Monitoring Mode = "monitoring"
	Paused     Mode = "paused"
)

type Scope struct {
	Sensor    string   `json:"sensor"`
	Interface string   `json:"interface"`
	VLANs     []uint16 `json:"vlans,omitempty"`
}

// Fact is a reproducible observation identity. Port is a destination service port.
type Fact struct {
	LeaseSeconds uint32 `json:"leaseSeconds,omitempty"`
	Bytes        uint64 `json:"bytes,omitempty"`
	Token        string `json:"token,omitempty"`
	Scope        Scope  `json:"scope"`
	Kind         string `json:"kind"`
	SrcIP        string `json:"srcIP,omitempty"`
	DstIP        string `json:"dstIP,omitempty"`
	MAC          string `json:"mac,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Value        string `json:"value,omitempty"`
	Provenance   string `json:"provenance,omitempty"`
}

func (f *Fact) normalize() error {
	if f.Scope.Sensor == "" || f.Scope.Interface == "" || len(f.Scope.Sensor) > 256 || len(f.Scope.Interface) > 256 || len(f.Scope.VLANs) > 4 {
		return fmt.Errorf("sensor and interface are required; scope exceeds limits")
	}
	for _, vlan := range f.Scope.VLANs {
		if vlan > 4095 {
			return fmt.Errorf("invalid VLAN %d", vlan)
		}
	}
	for _, value := range []*string{&f.SrcIP, &f.DstIP} {
		if *value != "" {
			addr, err := netip.ParseAddr(*value)
			if err != nil || addr.Zone() != "" {
				return fmt.Errorf("invalid IP %q", *value)
			}
			*value = addr.Unmap().String()
		}
	}
	if f.MAC != "" {
		mac, err := net.ParseMAC(f.MAC)
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("invalid MAC %q", f.MAC)
		}
		f.MAC = mac.String()
	}
	if len(f.Value) > 1024 || len(f.Provenance) > 256 {
		return fmt.Errorf("fact exceeds field limits")
	}
	if len(f.Token) > 128 {
		return fmt.Errorf("flow token exceeds limit")
	}
	switch f.Kind {
	case "traffic":
		if f.SrcIP == "" || f.Bytes > 1<<20 {
			return fmt.Errorf("traffic requires source and bounded captured bytes")
		}
	case "device":
		if f.MAC == "" {
			return fmt.Errorf("device requires MAC")
		}
	case "binding":
		if f.SrcIP == "" || f.MAC == "" {
			return fmt.Errorf("binding requires IP and MAC")
		}
	case "edge":
		if f.SrcIP == "" || f.DstIP == "" {
			return fmt.Errorf("edge requires endpoints")
		}
	case "service", "resolver":
		if f.SrcIP == "" || f.DstIP == "" || f.Port == 0 || (f.Protocol != "tcp" && f.Protocol != "udp") {
			return fmt.Errorf("service requires endpoints, protocol and port")
		}
	case "dns":
		if f.SrcIP == "" || f.Value == "" {
			return fmt.Errorf("DNS requires source and name")
		}
		f.Value = strings.TrimSuffix(strings.ToLower(f.Value), ".")
		if f.Value == "" {
			return fmt.Errorf("DNS name is empty")
		}
	case "prefix":
		prefix, err := netip.ParsePrefix(f.Value)
		if err != nil {
			return fmt.Errorf("invalid prefix: %w", err)
		}
		f.Value = prefix.Masked().String()
		if f.Provenance != "configured" && f.Provenance != "interface" && f.Provenance != "dhcp" && f.Provenance != "router-advertisement" {
			return fmt.Errorf("prefix provenance is required")
		}
	case "geo":
		if f.SrcIP == "" || f.DstIP == "" || f.Value == "" {
			return fmt.Errorf("geography requires endpoints and value")
		}
	default:
		return fmt.Errorf("unknown fact kind %q", f.Kind)
	}
	return nil
}

func factID(f Fact) string {
	if f.Kind == "geo" {
		f.DstIP = ""
		f.Provenance = ""
	}
	f.Token = ""
	f.Bytes = 0
	f.LeaseSeconds = 0
	if f.Kind == "binding" {
		f.Provenance = ""
		f.DstIP = ""
	}
	data, _ := json.Marshal(f)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

type Observation struct {
	Fact      Fact   `json:"fact"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
	Samples   uint64 `json:"samples"`
}

type Decision struct {
	IDs        []string `json:"ids,omitempty"`
	At         int64    `json:"at"`
	Action     string   `json:"action"`
	Reason     string   `json:"reason"`
	Version    uint64   `json:"version"`
	BaselineID string   `json:"baselineId"`
}

type Snapshot struct {
	Labels          map[string]AssetLabel  `json:"labels"`
	Corrections     map[string]Fact        `json:"corrections"`
	Leases          map[string]Lease       `json:"leases"`
	Rates           map[string]RateStats   `json:"rates"`
	ApprovedRates   map[string]RateModel   `json:"approvedRates"`
	Policy          Policy                 `json:"policy"`
	Activity        map[string]Activity    `json:"activity"`
	WindowOverflow  uint64                 `json:"windowOverflow"`
	Error           string                 `json:"error,omitempty"`
	Schema          int                    `json:"schema"`
	Mode            Mode                   `json:"mode"`
	ResumeMode      Mode                   `json:"resumeMode,omitempty"`
	Version         uint64                 `json:"version"`
	BaselineID      string                 `json:"baselineId"`
	LearningStarted int64                  `json:"learningStarted"`
	Watermark       int64                  `json:"watermark"`
	Samples         uint64                 `json:"samples"`
	Overflow        uint64                 `json:"overflow"`
	OutOfOrder      uint64                 `json:"outOfOrder"`
	MinLearningNS   int64                  `json:"minLearningNS"`
	MinSamples      uint64                 `json:"minSamples"`
	MaxFacts        int                    `json:"maxFacts"`
	Observed        map[string]Observation `json:"observed"`
	Approved        map[string]Fact        `json:"approved"`
	Suppressed      map[string]string      `json:"suppressed"`
	Decisions       []Decision             `json:"decisions"`
}

type AssetLabel struct {
	Fact  Fact   `json:"fact"`
	Name  string `json:"name"`
	Role  string `json:"role,omitempty"`
	Notes string `json:"notes,omitempty"`
}

type Lease struct {
	Fact    Fact  `json:"fact"`
	At      int64 `json:"at"`
	Expires int64 `json:"expires"`
}

type InventoryEdit struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Role    string `json:"role,omitempty"`
	Notes   string `json:"notes,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	Reason  string `json:"reason"`
	Version uint64 `json:"version"`
}

type Config struct {
	Policy      *Policy
	Path        string
	MinLearning time.Duration
	MinSamples  uint64
	MaxFacts    int
	DedupWindow time.Duration
}

type AlertSink interface{ WriteAlert(*types.Alert) error }

type Evidence struct {
	Related    []Fact `json:"related,omitempty"`
	Count      int    `json:"count,omitempty"`
	WindowNS   int64  `json:"windowNS,omitempty"`
	Schema     int    `json:"schema"`
	Detector   string `json:"detector"`
	FactID     string `json:"factId"`
	Observed   Fact   `json:"observed"`
	Expected   string `json:"expected"`
	Version    uint64 `json:"baselineVersion"`
	BaselineID string `json:"baselineId"`
}

type Policy struct {
	Maintenance     []Maintenance `json:"maintenance,omitempty"`
	DeniedCountries []string      `json:"deniedCountries,omitempty"`
	DeniedASNs      []string      `json:"deniedASNs,omitempty"`
	RateWindows     uint64        `json:"rateWindows"`
	RateMultiplier  float64       `json:"rateMultiplier"`
	WindowNS        int64         `json:"windowNS"`
	Fanout          int           `json:"fanout"`
	RDPAttempts     int           `json:"rdpAttempts"`
	ApprovedSources []string      `json:"approvedSources,omitempty"`
}

type Maintenance struct {
	Source string `json:"source"`
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
}

type Activity struct {
	Fact Fact  `json:"fact"`
	At   int64 `json:"at"`
}

func DefaultPolicy() Policy {
	return Policy{WindowNS: int64(time.Minute), Fanout: 5, RDPAttempts: 10, RateWindows: 4, RateMultiplier: 4}
}

type RateModel struct {
	Windows     uint64  `json:"windows"`
	PacketsMean float64 `json:"packetsMean"`
	PacketsM2   float64 `json:"packetsM2"`
	BytesMean   float64 `json:"bytesMean"`
	BytesM2     float64 `json:"bytesM2"`
}

type RateStats struct {
	Fact    Fact      `json:"fact"`
	Start   int64     `json:"start"`
	Packets uint64    `json:"packets"`
	Bytes   uint64    `json:"bytes"`
	Model   RateModel `json:"model"`
}
