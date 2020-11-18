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

package core

import (
	"github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

// DecoderAPI describes functionality of a decoder.
type DecoderAPI interface {

	// PostInitFunc is called after the decoder has been initialized
	PostInitFunc() error

	// DeInitFunc is called prior to teardown
	DeInitFunc() error

	// GetName returns the name of the decoder
	GetName() string

	// SetWriter sets the netcap writer to use for the decoder
	SetWriter(io.AuditRecordWriter)

	// GetType returns the netcap type of the decoder
	GetType() types.Type

	// GetDescription returns the description of the decoder
	GetDescription() string

	// GetChan returns a channel to receive serialized audit records from the decoder
	GetChan() <-chan []byte

	// Destroy initiates teardown
	Destroy() (string, int64)

	// NumRecords returns the number of processed audit records
	NumRecords() int64
}
