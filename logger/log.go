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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"path/filepath"
)

const (
	logFilePermission = 0o755
)

var (
// ReassemblyLog is the reassembly logger.
//ReassemblyLog = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)

// ReassemblyLogFileHandle is the file handle for the reassembly logger.
//ReassemblyLogFileHandle *os.File

// DebugLog is the debug logger.
//DebugLog = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)

// DebugLogFileHandle is the file handle for the debug logger.
//DebugLogFileHandle *os.File
)

// InitZapLogger can be used for high performance logging.
// - name is the log filename.
// - each pkg should init a dedicated local! logger and use it on the main structure.
// - outpath must exist in advance.
func InitZapLogger(outpath, name string, debug bool) (*zap.Logger, *os.File, error) {
	fileHandle, err := os.OpenFile(
		filepath.Join(outpath, name+".log"),
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		logFilePermission,
	)
	if err != nil {
		return nil, nil, err
	}

	var level zap.LevelEnablerFunc
	if debug {
		level = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return true // enable all
		})
	} else {
		level = zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
			return lvl > zapcore.DebugLevel // enable all above debug
		})
	}


	// Join the outputs, encoders, and level-handling functions into
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

// InitLoggers initializes the loggers for the given output path.
//func InitLoggers(outpath string) {
//	var err error
//
//	DebugLogFileHandle, err = os.OpenFile(filepath.Join(outpath, "debug.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	DebugLog.SetOutput(DebugLogFileHandle)
//
//	ReassemblyLogFileHandle, err = os.OpenFile(filepath.Join(outpath, "reassembly.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	ReassemblyLog.SetOutput(ReassemblyLogFileHandle)
//}

// CloseLogFiles closes the logfile handles.
//func CloseLogFiles() []error {
//	var errs []error
//
//	if ReassemblyLogFileHandle != nil {
//		err := ReassemblyLogFileHandle.Close()
//		if err != nil {
//			errs = append(errs, err)
//		}
//	}
//
//	if DebugLogFileHandle != nil {
//		err := DebugLogFileHandle.Close()
//		if err != nil {
//			errs = append(errs, err)
//		}
//	}
//
//	return errs
//}
