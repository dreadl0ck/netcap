/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package types

import (
	"encoding/hex"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsSNAP = []string{
	"Timestamp",
	"OrganizationalCode",
	"Type",
}

func (s SNAP) CSVHeader() []string {
	return filter(fieldsSNAP)
}

func (s SNAP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		hex.EncodeToString(s.OrganizationalCode),
		formatInt32(s.Type),
	})
}

func (s SNAP) NetcapTimestamp() string {
	return s.Timestamp
}

func (u SNAP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}

var snapMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_SNAP.String()),
		Help: Type_NC_SNAP.String() + " audit records",
	},
	fieldsSNAP[1:],
)

func init() {
	prometheus.MustRegister(snapMetric)
}

func (a SNAP) Inc() {
	snapMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}
