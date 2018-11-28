/*
 * NETCAP - Network Capture Toolkit
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
	"strings"
)

func (s SIP) CSVHeader() []string {
	return filter([]string{
		"Timestamp",
		"OrganizationalCode",
		"Type",
	})
}

func (s SIP) CSVRecord() []string {
	return filter([]string{
		formatTimestamp(s.Timestamp),
		s.Timestamp,                      //  string `protobuf:"bytes,1,opt,name=Timestamp,proto3" json:"Timestamp,omitempty"`
		formatInt32(s.Version),           //  int32 `protobuf:"varint,2,opt,name=Version,proto3" json:"Version,omitempty"`
		formatInt32(s.Method),            //   int32 `protobuf:"varint,3,opt,name=Method,proto3" json:"Method,omitempty"`
		strings.Join(s.Headers, "/"),     //  []string `protobuf:"bytes,4,rep,name=Headers,proto3" json:"Headers,omitempty"`
		strconv.FormatBool(s.IsResponse), //            bool     `protobuf:"varint,5,opt,name=IsResponse,proto3" json:"IsResponse,omitempty"`
		formatInt32(s.ResponseCode),      //          int32    `protobuf:"varint,6,opt,name=ResponseCode,proto3" json:"ResponseCode,omitempty"`
		s.ResponseStatus,                 //        string   `protobuf
	})
}

func (s SIP) NetcapTimestamp() string {
	return s.Timestamp
}
