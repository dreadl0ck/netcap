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
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dreadl0ck/cryptoutils"
	gzip "github.com/klauspost/pgzip"
	"go.uber.org/zap"

	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/decoder/core"
	"github.com/dreadl0ck/netcap/decoder/stream/file"
	"github.com/dreadl0ck/netcap/defaults"
	"github.com/dreadl0ck/netcap/types"
	"github.com/dreadl0ck/netcap/utils"
)

var reassemblyLog = zap.NewNop()

// SetLogger configures the logger for this package.
func SetLogger(l *zap.Logger) {
	reassemblyLog = l
}

// SaveFile TODO: create a structure for passing all the args
func SaveFile(conv *core.ConversationInfo, source, name string, err error, body []byte, encoding []string, host string, contentType string) error {
	reassemblyLog.Info("SaveFile",
		zap.String("source", source),
		zap.String("name", name),
		zap.Error(err),
		zap.Int("bodyLength", len(body)),
		zap.Strings("encoding", encoding),
		zap.String("host", host),
	)

	// prevent saving zero bytes
	if len(body) == 0 {
		return nil
	}

	if name == "" || name == "/" {
		name = "unknown"
	}

	var (
		fileName string

		// detected content type
		cType = trimEncoding(http.DetectContentType(body))

		// root path
		root = path.Join(decoderconfig.Instance.Out, decoderconfig.Instance.FileStorage, cType)

		// file extension
		ext = file.ExtensionForContentType(cType)

		// file basename
		base = filepath.Clean(name+"-"+path.Base(utils.CleanIdent(conv.Ident))) + ext
	)

	if err != nil {
		base = "incomplete-" + base
	}

	if filepath.Ext(name) == "" {
		fileName = name + ext
	} else {
		fileName = name
	}

	// make sure root path exists
	err = os.MkdirAll(root, defaults.DirectoryPermission)
	if err != nil {
		reassemblyLog.Error("failed to create directory",
			zap.String("path", root),
			zap.Int("perm", defaults.DirectoryPermission),
		)
	}

	base = path.Join(root, base)

	if len(base) > 250 {
		base = base[:250] + "..."
	}

	if base == decoderconfig.Instance.FileStorage {
		base = path.Join(decoderconfig.Instance.Out, decoderconfig.Instance.FileStorage, "noname")
	}

	var (
		target = base
		n      = 0
	)

	for {
		_, errStat := os.Stat(target)
		if errStat != nil {
			break
		}

		if err != nil {
			target = path.Join(root, filepath.Clean("incomplete-"+name+"-"+utils.CleanIdent(conv.Ident))+"-"+strconv.Itoa(n)+file.ExtensionForContentType(cType))
		} else {
			target = path.Join(root, filepath.Clean(name+"-"+utils.CleanIdent(conv.Ident))+"-"+strconv.Itoa(n)+file.ExtensionForContentType(cType))
		}

		n++
	}

	// fmt.Println("saving file:", target)

	f, err := os.Create(target)
	if err != nil {
		reassemblyLog.Error(
			"failed to create file",
			zap.String("ident", conv.Ident),
			zap.String("target", target),
			zap.Error(err),
		)

		return err
	}

	// explicitly declare io.Reader interface
	var (
		r             io.Reader
		length        int
		hash          string
		cTypeDetected = trimEncoding(http.DetectContentType(body))
	)

	// now assign a new buffer
	r = bytes.NewBuffer(body)

	// Decode gzip
	if len(encoding) > 0 && (encoding[0] == "gzip" || encoding[0] == "deflate") {
		r, err = gzip.NewReader(r)
		if err != nil {
			reassemblyLog.Error(
				"failed to gzip decode",
				zap.String("ident", conv.Ident),
				zap.Error(err),
			)
		}
	}

	// Decode base64
	if len(encoding) > 0 && (encoding[0] == "base64") {
		r, _ = base64.NewDecoder(base64.StdEncoding, r).(io.Reader)
	}

	if err == nil {
		w, errCopy := io.Copy(f, r)
		if errCopy != nil {
			reassemblyLog.Error(
				"failed to save file",
				zap.String("ident", conv.Ident),
				zap.String("target", target),
				zap.Int64("bytesWritten", w),
				zap.Error(errCopy),
			)
		} else {
			reassemblyLog.Debug(
				"saved file",
				zap.String("ident", conv.Ident),
				zap.String("target", target),
				zap.Int64("bytesWritten", w),
			)
		}

		if _, ok := r.(*gzip.Reader); ok {
			errClose := r.(*gzip.Reader).Close()
			if errClose != nil {
				reassemblyLog.Error(
					"failed to close gzip reader",
					zap.String("ident", conv.Ident),
					zap.String("target", target),
					zap.Error(errClose),
				)
			}
		}

		errClose := f.Close()
		if errClose != nil {
			reassemblyLog.Error(
				"failed to close file handle",
				zap.String("ident", conv.Ident),
				zap.String("target", target),
				zap.Error(errClose),
			)
		}

		// TODO: refactor to avoid reading the file contents into memory again
		body, err = ioutil.ReadFile(target)
		if err == nil {
			// set hash to value for decompressed content and update size
			hash = hex.EncodeToString(cryptoutils.MD5Data(body))
			length = len(body)

			// update content type
			cTypeDetected = trimEncoding(http.DetectContentType(body))

			// make sure root path exists
			createContentTypePathIfRequired(path.Join(decoderconfig.Instance.Out, decoderconfig.Instance.FileStorage, cTypeDetected))

			// switch the file extension and the path for the updated content type
			ext = filepath.Ext(target)

			// create new target: trim extension from old one and replace
			// and replace the old content type in the path
			newTarget := strings.Replace(strings.TrimSuffix(target, ext), cType, cTypeDetected, 1) + file.ExtensionForContentType(cTypeDetected)

			err = os.Rename(target, newTarget)
			if err == nil {
				target = newTarget
			} else {
				fmt.Println("failed to rename file after decompression", err)
			}
		}
	} else {
		hash = hex.EncodeToString(cryptoutils.MD5Data(body))
		length = len(body)
	}

	// set the value for the provided content type to the value from the first content type detection
	// if none was provided
	if contentType == "" {
		contentType = cType
	}

	// write file to disk
	file.WriteFile(&types.File{
		// TODO: use the actual timestamp when file has been transferred
		Timestamp:           conv.FirstClientPacket.UnixNano(),
		Name:                fileName,
		Length:              int64(length),
		Hash:                hash,
		Location:            target,
		Ident:               conv.Ident,
		Source:              source,
		ContentType:         contentType,
		ContentTypeDetected: cTypeDetected,
		// TODO: set the actual flow direction of the file, not the one of the connection
		SrcIP:   conv.ClientIP,
		DstIP:   conv.ServerIP,
		SrcPort: conv.ServerPort,
		DstPort: conv.ClientPort,
		Host:    host,
	})

	return nil
}
