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

package encoder

import (
	"fmt"
	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/types"
	"github.com/golang/protobuf/proto"
)

var pop3Encoder = CreateCustomEncoder(types.Type_NC_POP3, "POP3", func(d *CustomEncoder) error {

	// TODO: pop3 should not depend on HTTP decoder
	HTTPActive = true

	// TODO: also done in HTTP decoder set file storage via flag
	if *fileStorage != "" {
		FileStorage = *fileStorage
	}

	return nil
}, func(packet gopacket.Packet) proto.Message {
	// encoding func is nil, because the processing happens after TCP stream reassembly
	return nil
}, func(e *CustomEncoder) error {

	// de-init: finishes processing
	// and prints statistics

	fmt.Println("pop3Encoder.numRequests", e.numRequests)
	fmt.Println("pop3Encoder.numResponses", e.numResponses)
	fmt.Println("pop3Encoder.numUnmatchedResp", e.numUnmatchedResp)
	fmt.Println("pop3Encoder.numNilRequests", e.numNilRequests)
	fmt.Println("pop3Encoder.numFoundRequests", e.numFoundRequests)
	fmt.Println("pop3Encoder.numUnansweredRequests", e.numUnansweredRequests)

	return nil
})
