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

package service

import (
	"bytes"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/internal/aggregate"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type service struct {
	sync.Mutex
	*types.Service

	// track unique applications detected via DPI for flows associated with this service
	applications map[string]struct{}
	flowIDs      map[string]struct{}
}

// AddFlow requires the service lock, or an unpublished service.
func (s *service) AddFlow(id string) {
	if s.flowIDs == nil {
		s.flowIDs = make(map[string]struct{}, len(s.Flows)+1)
		for _, existing := range s.Flows {
			s.flowIDs[existing] = struct{}{}
		}
	}
	if _, exists := s.flowIDs[id]; !exists {
		s.flowIDs[id] = struct{}{}
		s.Flows = append(s.Flows, id)
	}
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicServiceMap struct {
	sync.Mutex
	operations sync.RWMutex
	// map server IP + Port to service
	Items map[string]*service
}

// Size returns the number of elements in the Items map.
func (a *atomicServiceMap) Size() int {
	a.operations.RLock()
	defer a.operations.RUnlock()
	if decoderconfig.Instance.AggregateStore != nil {
		return int(storedServices.Load())
	}
	a.Lock()
	defer a.Unlock()

	return len(a.Items)
}

// Store ServiceStore holds all tcp service banners.
var Store = &atomicServiceMap{
	Items: make(map[string]*service),
}

// ResetStore clears all services from memory
// This should be called when resetting state between processing different files
func ResetStore() {
	Store.operations.Lock()
	defer Store.operations.Unlock()
	if decoderconfig.Instance.AggregateStore != nil {
		_ = decoderconfig.Instance.AggregateStore.Do(func(tx *aggregate.Tx) error { return tx.Delete("service/") })
	}
	storedServices.Store(0)
	Store.Lock()
	Store.Items = make(map[string]*service)
	Store.Unlock()
}

// addInfo is util to append information to a string using a delimiter
// information will be deduplicated.
func addInfo(old string, new string) string {
	if len(old) == 0 {
		return new
	} else if len(new) == 0 {
		return old
	} else {
		// only append info that is not already present
		if !strings.Contains(old, new) {
			var b strings.Builder
			b.WriteString(old)
			b.WriteString(" | ")
			b.WriteString(new)

			return b.String()
		}

		return old
	}
}

// NewService creates a new network service.
func NewService(ts int64, numBytesServer, numBytesClient int, ip string) *service {
	var host string
	if resolvers.CurrentConfig.ReverseDNS {
		host = strings.Join(resolvers.LookupDNSNames(ip), "; ")
	} else if resolvers.CurrentConfig.LocalDNS {
		host = resolvers.LookupDNSNameLocal(ip)
	}

	return &service{
		Service: &types.Service{
			Timestamp:   ts,
			BytesServer: int32(numBytesServer),
			BytesClient: int32(numBytesClient),
			Hostname:    host,
		},
		applications: make(map[string]struct{}),
	}
}

// PreferObservation keeps one deterministic representative when several flows
// target the same service. Callers must hold the service lock.
func (s *service) PreferObservation(banner []byte, ts int64, numBytesServer, numBytesClient int) bool {
	current := []byte(s.Banner)
	prefer := len(banner) > len(current) ||
		(len(banner) == len(current) && bytes.Compare(banner, current) < 0) ||
		(bytes.Equal(banner, current) && (ts < s.Timestamp ||
			(ts == s.Timestamp && (int32(numBytesServer) > s.BytesServer ||
				(int32(numBytesServer) == s.BytesServer && int32(numBytesClient) > s.BytesClient)))))
	if !prefer {
		return false
	}
	s.Banner = string(banner)
	s.Timestamp = ts
	s.BytesServer = int32(numBytesServer)
	s.BytesClient = int32(numBytesClient)
	return true
}

// ResetProbeMatch clears fields derived from a previously selected banner.
// Applications and port metadata come from independent sources and remain.
func (s *service) ResetProbeMatch() {
	s.Name = s.PortName
	s.Product = ""
	s.Vendor = ""
	s.Version = ""
	s.Notes = ""
	s.OS = ""
	s.MatchedProbeID = ""
	s.DetectedProtocolName = ""
}

// AddApplications adds DPI-detected application protocols to a service.
// This function is thread-safe and can be called from packet decoders.
func AddApplications(serviceIdent string, applications []string) {
	Store.operations.RLock()
	defer Store.operations.RUnlock()
	lock := observationLock(serviceIdent)
	lock.Lock()
	defer lock.Unlock()
	if decoderconfig.Instance.AggregateStore != nil {
		addStoredApplications(serviceIdent, applications)
		return
	}
	Store.Lock()
	defer Store.Unlock()

	if serv, ok := Store.Items[serviceIdent]; ok {
		serv.Lock()
		defer serv.Unlock()

		if serv.applications == nil {
			serv.applications = make(map[string]struct{})
		}

		for _, app := range applications {
			serv.applications[app] = struct{}{}
		}
	}
}
