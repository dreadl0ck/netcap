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

package utils

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dreadl0ck/gopacket"
	"github.com/mgutz/ansi"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/credentials"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/reassembly"
	"github.com/dreadl0ck/netcap/utils"
)

// TODO: remove dups
const (
	binaryFileExtension = ".bin"
	protoTCP            = "TCP"
	protoUDP            = "UDP"
)

// SaveConversation will save TCP / UDP conversations to disk
// this also invokes the harvesters on the conversation banner
func SaveConversation(proto string, conversation core.DataFragments, ident string, firstPacket time.Time, transport gopacket.Flow) error {
	// prevent processing zero bytes
	if len(conversation) == 0 || conversation.Size() == 0 {
		return nil
	}

	// fmt.Println("saving conv", conversation.size(), ident)

	banner := createBannerFromConversation(conversation)
	credentials.RunHarvesters(banner, transport, ident, firstPacket)

	if !decoderconfig.Instance.SaveConns {
		return nil
	}

	var (
		typ = getServiceName(banner, transport, proto)

		// path for storing the data
		root = filepath.Join(decoderconfig.Instance.Out, strings.ToLower(proto), typ)

		// file basename
		base = filepath.Clean(path.Base(utils.CleanIdent(ident))) + binaryFileExtension
	)

	// make sure root path exists
	err := os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		reassemblyLog.Warn("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
		)
	}

	base = path.Join(root, base)

	reassemblyLog.Info("saveConversation", zap.String("base", base))

	Stats.Lock()
	switch proto {
	case protoTCP:
		Stats.SavedTCPConnections++
	case protoUDP:
		Stats.SavedUDPConnections++
	}
	Stats.Unlock()

retry:
	// append to files
	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, defaults.FilePermission)
	if err != nil {

		reassemblyLog.Error(
			"failed to create create path",
			zap.String("path", base),
			zap.Error(err),
		)

		// sleep and try again to handle too many open files error
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(500 * time.Millisecond)

			goto retry
		}

		return err
	}

	// TODO: make buffer size configurable
	w := bufio.NewWriterSize(f, 4096)

	if proto == protoTCP {
		// create the buffer with the entire conversation
		for _, d := range conversation {

			if d.Direction() == reassembly.TCPDirClientToServer {
				_, _ = w.WriteString(ansi.Red)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			} else {
				_, _ = w.WriteString(ansi.Blue)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			}

			if decoderconfig.Instance.Debug {
				var ts string
				if d.Context() != nil {
					ts = "\n[" + d.Context().GetCaptureInfo().Timestamp.String() + "]\n"
				}

				_, _ = w.WriteString(ts)
			}
		}
	} else { // UDP
		clientTransport := conversation[0].Transport()
		for _, d := range conversation {
			if d.Transport() == clientTransport {
				// client
				_, _ = w.WriteString(ansi.Red)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			} else {
				// server
				_, _ = w.WriteString(ansi.Blue)
				_, _ = w.Write(d.Raw())
				_, _ = w.WriteString(ansi.Reset)
			}
			if decoderconfig.Instance.Debug {
				_, _ = w.WriteString("\n[" + d.CaptureInfo().Timestamp.String() + "]\n")
			}
		}
	}

	err = w.Flush()
	if err != nil {
		reassemblyLog.Info("failed to flush buffer",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.String("proto", proto),
		)
	}

	err = f.Sync()
	if err != nil {
		reassemblyLog.Info("failed to sync file",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.String("proto", proto),
		)
	}

	// close file
	err = f.Close()
	if err != nil {
		reassemblyLog.Error(
			"failed to close conversation file",
			zap.String("path", base),
			zap.Error(err),
		)
	} else {
		reassemblyLog.Info("saved conversation",
			zap.String("ident", ident),
			zap.String("proto", proto),
			zap.String("base", base),
			zap.String("proto", proto),
		)
	}

	return nil
}

func createBannerFromConversation(conversation core.DataFragments) []byte {
	var (
		banner    = make([]byte, 0, decoderconfig.Instance.HarvesterBannerSize)
		processed int
	)

	// copy c.HarvesterBannerSize number of bytes from the raw conversation
	// to use for the credential harvesters
	for _, d := range conversation {
		for _, b := range d.Raw() {
			if processed >= decoderconfig.Instance.HarvesterBannerSize {
				break
			}

			processed++
			banner = append(banner, b)
		}
	}

	return banner
}
