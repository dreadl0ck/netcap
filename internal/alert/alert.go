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

package alert

import (
	"sync"

	"github.com/dreadl0ck/netcap/types"
)

// Manager keeps track of generated alerts to perform deduplication,
// and provides an interface to fetch alerts in a configurable interval.
type Manager struct {

	// current alerts hashmap
	alerts map[string]*types.Alert

	// allow thread safe access
	sync.Mutex
}

// AddAlert will add an alert
func (a *Manager) AddAlert(alert *types.Alert) {

	a.Lock()
	defer a.Unlock()

	// TODO: deduplicate and keep track of the number of times an alert was fired.
	a.alerts[alert.Name] = alert
}

// FetchAlerts fetches all alerts from the manager
// make configurable, add timer etc
func (a *Manager) FetchAlerts() map[string]*types.Alert {
	return a.alerts
}
