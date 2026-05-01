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

package secret

import (
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/decoder"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/internal/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var credLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Name:        DecoderName,
	Description: "Secrets to authenticate to a service, like a username and password combination, or a token, api key, etc.",
	Type:        types.Type_NC_Secret,
	PostInit: func(d *decoder.AbstractDecoder) (err error) {

		useHarvesters = true

		credLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"credentials",
			decoderconfig.Instance.Debug,
		)

		if err != nil {
			return err
		}

		// Load harvesters configuration
		var config *HarvestersConfigFile
		if decoderconfig.Instance.HarvestersConfigPath != "" {
			config, err = LoadHarvestersConfig(decoderconfig.Instance.HarvestersConfigPath)
			if err != nil {
				log.Printf("Failed to load harvesters config from %s: %v. Using default configuration.\n",
					decoderconfig.Instance.HarvestersConfigPath, err)
				config = nil
			}
		}

		// Initialize harvesters with config (will use defaults if config is nil)
		if err := InitializeHarvesters(config); err != nil {
			return err
		}

		// Handle legacy custom regex flag (if provided, add to harvesters)
		if decoderconfig.Instance.CustomRegex != "" {
			r, errCompile := regexp.Compile(decoderconfig.Instance.CustomRegex)
			if errCompile != nil {
				return errCompile
			}

			// Create a Harvester struct for the custom regex
			customRegexHarvester := Harvester{
				Name:        "Custom Regex",
				Description: "Custom regex pattern: " + decoderconfig.Instance.CustomRegex,
				HarvesterFunc: func(data []byte, ident string, ts time.Time) *types.Secret {
					matches := r.FindSubmatch(data)
					if len(matches) > 1 {
						var notes strings.Builder
						for _, m := range matches {
							notes.WriteString(" " + string(m) + " ")
						}

						return &types.Secret{
							Notes: notes.String(),
						}
					}

					return nil
				},
			}
			tcpConnectionHarvesters = append(tcpConnectionHarvesters, customRegexHarvester)
		}

		return nil
	},
	DeInit: func(sd *decoder.AbstractDecoder) error {
		return credLog.Sync()
	},
}

// WriteSecret is a util that should be used to write credential audit to disk
// it will deduplicate the audit records to avoid repeating information on disk.
func WriteSecret(creds *types.Secret) {
	// Skip credentials with empty username AND password - they provide no useful information
	if creds.User == "" && creds.Password == "" {
		return
	}

	ident := creds.Service + creds.User + creds.Password

	// prevent saving duplicate credentials
	credStoreMu.Lock()
	if _, ok := credStore[ident]; ok {
		credStoreMu.Unlock()

		return
	}

	credStore[ident] = creds.Flow
	credStoreMu.Unlock()

	if decoderconfig.Instance.ExportMetrics {
		creds.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(creds)
	if err != nil {
		log.Fatal("failed to write proto: ", err)
	}
}
