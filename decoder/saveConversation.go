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
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// save TCP / UDP conversations to disk
func saveConversation(proto string, conversation dataFragments, ident string, firstPacket time.Time, transport gopacket.Flow) error {
	// prevent processing zero bytes
	if len(conversation) == 0 || conversation.size() == 0 {
		return nil
	}

	banner := createBannerFromConversation(conversation)
	runHarvesters(banner, transport, ident, firstPacket)

	if !conf.SaveConns {
		return nil
	}

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
	switch proto {
	case protoTCP:
		stats.savedTCPConnections++
	case protoUDP:
		stats.savedUDPConnections++
	}
	stats.Unlock()

	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {
		logReassemblyError("conversation-create", fmt.Sprintf("%s: failed to create %s", ident, base), err)

		return err
	}

	// TODO: make buffer size configurable
	w := bufio.NewWriterSize(f, 4096)

	if proto == protoTCP {
		// create the buffer with the entire conversation
		for _, d := range conversation {

			if d.direction() == reassembly.TCPDirClientToServer {
				w.WriteString(ansi.Red)
				w.Write(d.raw())
				w.WriteString(ansi.Reset)
			} else {
				w.WriteString(ansi.Blue)
				w.Write(d.raw())
				w.WriteString(ansi.Reset)
			}

			if conf.Debug {
				var ts string
				if d.context() != nil {
					ts = "\n[" + d.context().GetCaptureInfo().Timestamp.String() + "]\n"
				}

				w.WriteString(ts)
			}
		}
	} else {
		clientTransport := conversation[0].transport()
		for _, d := range conversation {
			if d.transport() == clientTransport {
				// client
				w.WriteString(ansi.Red)
				w.Write(d.raw())
				w.WriteString(ansi.Reset)
			} else {
				// server
				w.WriteString(ansi.Blue)
				w.Write(d.raw())
				w.WriteString(ansi.Reset)
			}
			if conf.Debug {
				w.WriteString("\n[" + d.captureInfo().Timestamp.String() + "]\n")
			}
		}
	}

	// close file
	err = f.Close()
	if err != nil {
		logReassemblyError("TCP connection", fmt.Sprintf("%s: failed to close TCP connection file %s", ident, base), err)
	} else {
		reassemblyLog.Info("saved conversation",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
		)
	}

	return nil
}

func createBannerFromConversation(conversation dataFragments) []byte {
	var (
		banner    = make([]byte, 0, conf.HarvesterBannerSize)
		processed int
	)

	// copy c.HarvesterBannerSize number of bytes from the raw conversation
	// to use for the credential harvesters
	for _, d := range conversation {
		for _, b := range d.raw() {
			if processed >= conf.HarvesterBannerSize {
				break
			}

			processed++
			banner = append(banner, b)
		}
	}

	return banner
}
