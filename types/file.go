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
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var fieldsFile = []string{
	"Timestamp",
	"Name",
	"Length",
	"Hash",
	"Location",
	"Ident",
	"Source",
	"ContentType",
	"SrcIP",
	"DstIP",
	"SrcPort",
	"DstPort",
}

func (a File) CSVHeader() []string {
	return filter(fieldsARP)
}

func (a File) CSVRecord() []string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return filter([]string{
		formatTimestamp(a.Timestamp),
		a.Name,
		formatInt64(a.Length),
		a.Hash,
		a.Location,
		a.Ident,
		a.Source,
		a.ContentType,
		a.Context.SrcIP,
		a.Context.DstIP,
		a.Context.SrcPort,
		a.Context.DstPort,
	})
}

func (a File) Time() string {
	return a.Timestamp
}

func (a File) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&a)
}

var fileMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: strings.ToLower(Type_NC_File.String()),
		Help: Type_NC_File.String() + " audit records",
	},
	fieldsARP[1:],
)

func init() {
	prometheus.MustRegister(fileMetric)
}

func (a File) Inc() {
	fileMetric.WithLabelValues(a.CSVRecord()[1:]...).Inc()
}

func (a *File) SetPacketContext(ctx *PacketContext) {}

func (a File) Src() string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return a.Context.SrcIP
}

func (a File) Dst() string {
	// prevent accessing nil pointer
	if a.Context == nil {
		a.Context = &PacketContext{}
	}
	return a.Context.DstIP
}
