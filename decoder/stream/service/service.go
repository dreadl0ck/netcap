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
	"sort"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var (
	serviceLog *zap.Logger
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_Service,
	Name:        "Service",
	Description: "A network service",
	PostInit: func(d *decoder.AbstractDecoder) error {
		var err error
		serviceLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"service",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}

		return initServiceProbes()
	},
	DeInit: func(e *decoder.AbstractDecoder) error {
		// flush writer
		var err error

		// stable output order: Store.Items is a map
		idents := make([]string, 0, len(Store.Items))
		for ident := range Store.Items {
			idents = append(idents, ident)
		}
		sort.Strings(idents)

		for _, ident := range idents {
			item := Store.Items[ident]
			item.Lock()

			// populate Applications from DPI results
			if len(item.applications) > 0 {
				item.Service.Applications = make([]string, 0, len(item.applications))
				for app := range item.applications {
					item.Service.Applications = append(item.Service.Applications, app)
				}
				// DetectedProtocolName below takes the first entry, so the map
				// order would otherwise decide which protocol gets reported.
				sort.Strings(item.Service.Applications)
			}

			// Set DetectedProtocolName based on available information
			if len(item.Service.Applications) > 0 {
				// Use the first DPI-detected application as the protocol name
				item.Service.DetectedProtocolName = item.Service.Applications[0]
			} else if item.Service.Product != "" {
				// Use product name if available from service probe matching
				item.Service.DetectedProtocolName = item.Service.Product
			} else if item.Service.Name != "" {
				// Fallback to the service name from port lookup
				item.Service.DetectedProtocolName = item.Service.Name
			}

			err = e.Writer.Write(item.Service)
			if err != nil {
				serviceLog.Error("failed to flush service audit record", zap.Error(err))
			}
			item.Unlock()

			atomic.AddInt64(&e.NumRecordsWritten, 1)
		}

		return serviceLog.Sync()
	},
}
