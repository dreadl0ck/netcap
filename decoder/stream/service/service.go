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

package service

import (
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/resolvers"
	"github.com/dreadl0ck/netcap/types"
)

type service struct {
	*types.Service
	sync.Mutex
}

// atomicDeviceProfileMap contains all connections and provides synchronized access.
type atomicServiceMap struct {
	// map server IP + Port to service
	Items map[string]*service
	sync.Mutex
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
	}
}

var (
	serviceLog        *zap.Logger
	serviceLogSugared *zap.SugaredLogger
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = decoder.NewStreamDecoder(
	types.Type_NC_Service,
	"Service",
	"A network service",
	func(d *decoder.StreamDecoder) error {
		var err error
		serviceLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"service",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}

		serviceLogSugared = serviceLog.Sugar()

		return initServiceProbes()
	},
	nil,
	func(e *decoder.StreamDecoder) error {
		// flush writer
		for _, item := range Store.Items {
			item.Lock()
			_ = e.Writer.Write(item.Service)
			item.Unlock()
		}

		return serviceLog.Sync()
	},
	nil,
)
