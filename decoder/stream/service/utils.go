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
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type service struct {
	sync.Mutex
	*types.Service

	// track unique applications detected via DPI for flows associated with this service
	applications map[string]struct{}
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicServiceMap struct {
	sync.Mutex
	// map server IP + Port to service
	Items map[string]*service
}

// Size returns the number of elements in the Items map.
func (a *atomicServiceMap) Size() int {
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

// AddApplications adds DPI-detected application protocols to a service.
// This function is thread-safe and can be called from packet decoders.
func AddApplications(serviceIdent string, applications []string) {
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
