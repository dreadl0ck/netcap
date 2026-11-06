/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package logger

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dreadl0ck/netcap/defaults"
)

// InitZapLogger can be used for high performance logging.
// The name is the log filename and the outpath must exist in advance.
func InitZapLogger(outpath, name string, debug bool) (*zap.Logger, *os.File, error) {
	if outpath == "" {
		outpath = "."
	}
	info, err := os.Stat(outpath)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() || filepath.Base(name) != name {
		return nil, nil, fmt.Errorf("invalid logger directory or name")
	}
	sink := &lazyLogFile{path: filepath.Join(outpath, name+".log")}

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
			sink,
			level,
		),
	)

	return zap.New(core), nil, nil
}

// Sync closes the current append handle. A later write safely reopens it.
type lazyLogFile struct {
	sync.Mutex
	path string
	file *os.File
}

func (f *lazyLogFile) Write(p []byte) (int, error) {
	f.Lock()
	defer f.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if f.file == nil {
		var err error
		f.file, err = os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, defaults.FilePermission)
		if err != nil {
			return 0, err
		}
	}
	return f.file.Write(p)
}
func (f *lazyLogFile) Sync() error {
	f.Lock()
	defer f.Unlock()
	if f.file == nil {
		return nil
	}
	err := f.file.Sync()
	closeErr := f.file.Close()
	f.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

// InitZapLoggerWithAtomicLevel creates a zap logger with an atomic level that can be changed at runtime.
// The name is the log filename and the outpath must exist in advance.
// Returns the logger, file handle, atomic level, and error.
func InitZapLoggerWithAtomicLevel(outpath, name string, debug bool) (*zap.Logger, *os.File, *zap.AtomicLevel, error) {
	fileHandle, err := os.OpenFile(
		filepath.Join(outpath, name+".log"),
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		defaults.FilePermission,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create atomic level - start with Debug if debug is true, Info otherwise
	atomicLevel := zap.NewAtomicLevel()
	if debug {
		atomicLevel.SetLevel(zapcore.DebugLevel)
	} else {
		atomicLevel.SetLevel(zapcore.InfoLevel)
	}

	// Join the outputs, decoders, and level-handling functions into
	// zapcore.Cores, then tee the cores together.
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		// If the data source only implements io.Writer, we can use zapcore.AddSync to add a no-op Sync
		// method. If its not safe for concurrent use, we can add a protecting mutex with zapcore.Lock.
		zapcore.AddSync(fileHandle),
		atomicLevel,
	)

	return zap.New(core), fileHandle, &atomicLevel, nil
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
