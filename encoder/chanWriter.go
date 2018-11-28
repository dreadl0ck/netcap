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

package encoder

// chanWriter writes into a []byte chan
type chanWriter struct {
	ch chan []byte
}

// TODO make chan buf size configurable
func newChanWriter() *chanWriter {
	return &chanWriter{make(chan []byte, 1024)}
}

func (w *chanWriter) Chan() <-chan []byte {
	return w.ch
}

func (w *chanWriter) Write(p []byte) (int, error) {
	w.ch <- p
	return len(p), nil
}

func (w *chanWriter) Close() error {
	close(w.ch)
	return nil
}
