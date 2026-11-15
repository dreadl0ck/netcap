package service

import (
	"encoding/base64"
	"hash/fnv"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/internal/utils"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
	"github.com/gopacket/gopacket"
)

type Observation struct {
	ID, FlowID, IP, Protocol string
	Port                     int32
	Timestamp                int64
	ServerBytes, ClientBytes int
	Banner                   []byte
}

var observationLocks [64]sync.Mutex
var storedServices atomic.Int64

func observationLock(id string) *sync.Mutex {
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	return &observationLocks[h.Sum64()%uint64(len(observationLocks))]
}

func fieldPrefix(id string) string {
	return "service/fields/" + base64.RawURLEncoding.EncodeToString([]byte(id)) + "/"
}

func newObservation(o Observation) *service {
	s := NewService(o.Timestamp, o.ServerBytes, o.ClientBytes, o.IP)
	s.Banner, s.IP, s.Port = string(o.Banner), o.IP, o.Port
	if o.Protocol != "" {
		s.Protocol = o.Protocol
		s.Name = resolvers.LookupServiceByPort(int(o.Port), o.Protocol)
		s.PortName = s.Name
	}
	return s
}

func ObserveFlowBanner(id, flow string, banner []byte, at time.Time, serverBytes, clientBytes int, network, transport gopacket.Flow, protocol string) (bool, error) {
	o := Observation{ID: id, FlowID: flow, Banner: banner, Timestamp: at.UnixNano(), ServerBytes: serverBytes, ClientBytes: clientBytes, Port: utils.DecodePort(transport.Dst().Raw())}
	if len(network.Dst().Raw()) > 0 {
		o.IP = network.Dst().String()
	}
	if len(transport.Dst().Raw()) > 0 {
		if _, err := strconv.Atoi(transport.Dst().String()); err == nil {
			o.Protocol = protocol
		}
	}
	return ObserveBanner(o)
}

// ObserveBanner serializes one endpoint's observations with a fixed lock set.
// Probe callbacks run outside the aggregate lock because they can emit software.
func ObserveBanner(o Observation) (bool, error) {
	Store.operations.RLock()
	defer Store.operations.RUnlock()
	lock := observationLock(o.ID)
	lock.Lock()
	defer lock.Unlock()
	state := decoderconfig.Instance.AggregateStore
	if state == nil {
		Store.Lock()
		s, found := Store.Items[o.ID]
		Store.Unlock()
		if !found {
			s = newObservation(o)
			s.AddFlow(o.FlowID)
			MatchServiceProbes(s, o.Banner, o.FlowID)
			Store.Lock()
			Store.Items[o.ID] = s
			Store.Unlock()
			return true, nil
		}
		s.Lock()
		defer s.Unlock()
		s.AddFlow(o.FlowID)
		if s.PreferObservation(o.Banner, o.Timestamp, o.ServerBytes, o.ClientBytes) {
			s.ResetProbeMatch()
			MatchServiceProbes(s, o.Banner, o.FlowID)
		}
		return false, nil
	}
	var s *service
	var found bool
	err := state.Do(func(tx *aggregate.Tx) error {
		wire, exists, err := tx.Get("service/base/" + o.ID)
		found = exists
		if err != nil || !exists {
			return err
		}
		s = &service{Service: &types.Service{}}
		return proto.Unmarshal(wire, s.Service)
	})
	if err != nil {
		return false, err
	}
	changed := !found
	if !found {
		s = newObservation(o)
		MatchServiceProbes(s, o.Banner, o.FlowID)
	} else if s.PreferObservation(o.Banner, o.Timestamp, o.ServerBytes, o.ClientBytes) {
		s.ResetProbeMatch()
		MatchServiceProbes(s, o.Banner, o.FlowID)
		changed = true
	}
	err = state.Do(func(tx *aggregate.Tx) error {
		if changed {
			wire, err := proto.Marshal(s.Service)
			if err != nil {
				return err
			}
			if err = tx.Put("service/base/"+o.ID, wire); err != nil {
				return err
			}
		}
		return tx.Put(fieldPrefix(o.ID)+"flows/"+base64.RawURLEncoding.EncodeToString([]byte(o.FlowID)), []byte(o.FlowID))
	})
	if err != nil {
		return false, err
	}
	if !found {
		storedServices.Add(1)
	}
	return !found, nil
}

func addStoredApplications(id string, apps []string) {
	_ = decoderconfig.Instance.AggregateStore.Do(func(tx *aggregate.Tx) error {
		_, found, err := tx.Get("service/base/" + id)
		if err != nil || !found {
			return err
		}
		for _, app := range apps {
			if err = tx.Put(fieldPrefix(id)+"apps/"+base64.RawURLEncoding.EncodeToString([]byte(app)), []byte(app)); err != nil {
				return err
			}
		}
		return nil
	})
}

func walkStoredServices(fn func(*types.Service, map[string]struct{}) error) error {
	last := ""
	for {
		var key string
		var s *types.Service
		apps := map[string]struct{}{}
		err := decoderconfig.Instance.AggregateStore.Do(func(tx *aggregate.Tx) error {
			var wire []byte
			var found bool
			var err error
			key, wire, found, err = tx.Next("service/base/", last)
			if err != nil || !found {
				return err
			}
			s = &types.Service{}
			if err = proto.Unmarshal(wire, s); err != nil {
				return err
			}
			prefix := fieldPrefix(key[len("service/base/"):])
			if err = tx.Each(prefix+"flows/", func(_ string, wire []byte) error { s.Flows = append(s.Flows, string(wire)); return nil }); err != nil {
				return err
			}
			return tx.Each(prefix+"apps/", func(_ string, wire []byte) error { apps[string(wire)] = struct{}{}; return nil })
		})
		if err != nil {
			return err
		}
		if s == nil {
			return nil
		}
		if err = fn(s, apps); err != nil {
			return err
		}
		last = key
	}
}
