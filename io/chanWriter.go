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

package io

// ChanProtoWriter writes into a []byte chan.
type ChanProtoWriter struct {
	ch chan []byte
}

// NewChanWriter returns a new channel writer instance.
// TODO make chan buf size configurable.
func NewChanWriter() *ChanProtoWriter {
	return &ChanProtoWriter{make(chan []byte, 1024)}
}

// Chan returns the byte channel used to receive data.
func (w *ChanProtoWriter) Chan() <-chan []byte {
	return w.ch
}

// WriteRecord writes a protocol buffer into the channel writer.
func (w *ChanProtoWriter) Write(p []byte) (int, error) {
	w.ch <- p

	return len(p), nil
}

// Close will close the channel writer.
func (w *ChanProtoWriter) Close() error {
	close(w.ch)

	return nil
}
