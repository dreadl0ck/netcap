/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017-2020 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package alert

import (
	"github.com/dreadl0ck/netcap/types"
	"sync"
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
