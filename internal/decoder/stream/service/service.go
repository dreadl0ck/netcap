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
	"errors"
	"sort"
	"sync/atomic"

	"github.com/dreadl0ck/netcap/internal/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/internal/decoder/config"
	decoderutils "github.com/dreadl0ck/netcap/internal/decoder/utils"
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
		Store.operations.Lock()
		defer Store.operations.Unlock()
		if decoderconfig.Instance.AggregateStore != nil {
			err := walkStoredServices(func(s *types.Service, apps map[string]struct{}) error { return writeService(e, s, apps) })
			return errors.Join(err, serviceLog.Sync())
		}
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
			err = errors.Join(err, writeService(e, item.Service, item.applications))
			item.Unlock()
		}

		return errors.Join(err, serviceLog.Sync())
	},
}

func writeService(d *decoder.AbstractDecoder, s *types.Service, apps map[string]struct{}) error {
	sort.Strings(s.Flows)
	if len(apps) > 0 {
		s.Applications = make([]string, 0, len(apps))
		for app := range apps {
			s.Applications = append(s.Applications, app)
		}
		sort.Strings(s.Applications)
	}
	if len(s.Applications) > 0 {
		s.DetectedProtocolName = decoderutils.CanonicalProtocol(s.Applications[0])
	} else if s.MatchedProbeID != "" {
		s.DetectedProtocolName = decoderutils.CanonicalProtocol(s.Name)
	} else {
		s.DetectedProtocolName = ""
	}
	if s.MatchedProbeID == "" {
		s.Name = s.DetectedProtocolName
	}
	if err := d.Writer.Write(s); err != nil {
		return err
	}
	atomic.AddInt64(&d.NumRecordsWritten, 1)
	return nil
}
