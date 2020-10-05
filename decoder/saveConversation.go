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

package decoder

import (
	"bufio"
	"fmt"
	"github.com/dreadl0ck/netcap/defaults"
	"go.uber.org/zap"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/dreadl0ck/netcap/utils"
)

// save TCP / UDP conversations to disk
func saveConversation(proto string, raw []byte, colored []byte, ident string, firstPacket time.Time, transport gopacket.Flow) error {
	// prevent processing zero bytes
	if len(raw) == 0 {
		return nil
	}

	banner := runHarvesters(raw, transport, ident, firstPacket)

	if !conf.SaveConns {
		return nil
	}

	// fmt.Println("save connection", ident, len(raw), len(colored))
	// fmt.Println(string(colored))

	var (
		typ = getServiceName(banner, transport)

		// path for storing the data
		root = filepath.Join(conf.Out, proto, typ)

		// file basename
		base = filepath.Clean(path.Base(utils.CleanIdent(ident))) + binaryFileExtension
	)

	// make sure root path exists
	err := os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		decoderLog.Warn("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
		)
	}

	base = path.Join(root, base)

	decoderLog.Info("saveConversation", zap.String("base", base))

	stats.Lock()
	stats.savedTCPConnections++
	stats.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {
		logReassemblyError("conversation-create", fmt.Sprintf("%s: failed to create %s", ident, base), err)

		return err
	}

	// do not colorize the data written to disk if its just a single keepalive byte
	if len(raw) == 1 {
		colored = raw
	}

	// TODO: make buffer size configurable
	w := bufio.NewWriterSize(f, 4096)
	n, err := w.Write(colored)

	// TODO: add benchmarks to see what is faster and causes less allocations / syscalls
	// save the colored version
	// assign a new buffer
	//r := bytes.NewBuffer(colored)
	//n, err := io.Copy(f, r)
	if err != nil {
		logReassemblyError(proto + " conversation", fmt.Sprintf("%s: failed to save TCP connection %s (l:%d)", ident, base, n), err)
	} else {
		reassemblyLog.Info("saved conversation",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.Int("bytesWritten", int(n)),
		)
	}

	err = f.Close()
	if err != nil {
		logReassemblyError("TCP connection", fmt.Sprintf("%s: failed to close TCP connection file %s (l:%d)", ident, base, n), err)
	}

	return nil
}