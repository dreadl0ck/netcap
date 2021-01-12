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

package logger

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/defaults"
)

// InitZapLogger can be used for high performance logging.
// The name is the log filename and the outpath must exist in advance.
func InitZapLogger(outpath, name string, debug bool) (*zap.Logger, *os.File, error) {
	fileHandle, err := os.OpenFile(
		filepath.Join(outpath, name+".log"),
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		defaults.FilePermission,
	)
	if err != nil {
		return nil, nil, err
	}

	var level zap.LevelEnablerFunc
	if debug {
		level = func(lvl zapcore.Level) bool {
			return true // enable all
		}
	} else {
		level = func(lvl zapcore.Level) bool {
			return lvl > zapcore.DebugLevel // enable all above debug
		}
	}

	// Join the outputs, decoders, and level-handling functions into
	// zapcore.Cores, then tee the cores together.
	core := zapcore.NewTee(
		//zapcore.NewCore(
		//	zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		//	zapcore.AddSync(fileHandle)
		//  allLevels,
		//),
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
			// If the data source only implements io.Writer, we can use zapcore.AddSync to add a no-op Sync
			// method. If its not safe for concurrent use, we can add a protecting mutex with zapcore.Lock.
			zapcore.AddSync(fileHandle),
			level,
		),
	)

	return zap.New(core), fileHandle, nil
}

// InitDebugLogger can be used for ANSI escape sequence colored and multi line debug logging.
// The name is the log filename and the outpath must exist in advance.
// When debug mode is not active, this function will init the logger with ioutil.Discard,
// and return a nil pointer for the file handle.
func InitDebugLogger(outpath, name string, debug bool) (*log.Logger, *os.File, error) {
	var (
		fileHandle *os.File
		err        error
		l          *log.Logger
	)

	if debug {
		fileHandle, err = os.OpenFile(
			filepath.Join(outpath, name+".log"),
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			defaults.FilePermission,
		)
		if err != nil {
			return nil, nil, err
		}

		l = log.New(fileHandle, "", log.Ldate|log.Lmicroseconds)
	} else {
		l = log.New(ioutil.Discard, "", log.Ldate|log.Lmicroseconds)
	}

	return l, fileHandle, nil
}
