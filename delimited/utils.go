/*
 * NETCAP - Network Capture Framework
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

package delimited

// copyData copies each record read from src to sink sequentially until src.Next().
// Note:
// - returns io.EOF or another error occurs.
// func copyData(sink sink, src dataSource) error {
//	for {
//		record, err := src.Next()
//
//		switch {
//		case err == io.EOF:
//			return nil
//		case err != nil:
//			return fmt.Errorf("read error while copying: %v", err)
//		default:
//			if err = sink.Put(record); err != nil {
//				return fmt.Errorf("write error while copying: %v", err)
//			}
//		}
//	}
// }
