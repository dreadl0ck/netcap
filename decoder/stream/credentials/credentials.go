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

package credentials

import (
	"log"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/dreadl0ck/netcap/decoder"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var credLog = zap.NewNop()

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Name:        DecoderName,
	Description: "Credentials represent a user and password combination to authenticate to a service",
	Type:        types.Type_NC_Credentials,
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

		if decoderconfig.Instance.CustomRegex != "" {
			r, errCompile := regexp.Compile(decoderconfig.Instance.CustomRegex)
			if errCompile != nil {
				return errCompile
			}

			tcpConnectionHarvesters = append(tcpConnectionHarvesters, func(data []byte, ident string, ts time.Time) *types.Credentials {
				matches := r.FindSubmatch(data)
				if len(matches) > 1 {
					notes := ""
					for _, m := range matches {
						notes += " " + string(m) + " "
					}

					return &types.Credentials{
						Notes: notes,
					}
				}

				return nil
			})
		}

		return nil
	},
	DeInit: func(sd *decoder.AbstractDecoder) error {
		return credLog.Sync()
	},
}

// WriteCredentials is a util that should be used to write credential audit to disk
// it will deduplicate the audit records to avoid repeating information on disk.
func WriteCredentials(creds *types.Credentials) {
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
