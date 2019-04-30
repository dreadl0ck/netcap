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
	"strconv"
)

func (s SCTP) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"SrcPort",
		"DstPort",
		"VerificationTag",
		"Checksum",
	})
}

func (s SCTP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		strconv.FormatUint(uint64(s.SrcPort), 10),
		strconv.FormatUint(uint64(s.DstPort), 10),
		strconv.FormatUint(uint64(s.VerificationTag), 10),
		strconv.FormatUint(uint64(s.Checksum), 10),
	})
}

func (s SCTP) NetcapTimestamp() string {
	return s.Timestamp
}

func (u SCTP) JSON() (string, error) {
	return jsonMarshaler.MarshalToString(&u)
}
