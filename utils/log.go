package utils

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const (
	logFilePermission = 0o755
)

var (
	ReassemblyLog           = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)
	ReassemblyLogFileHandle *os.File

	DebugLog           = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)
	DebugLogFileHandle *os.File
)

func InitLoggers(outpath string) {
	var err error
	DebugLogFileHandle, err = os.OpenFile(filepath.Join(outpath, "debug.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
	if err != nil {
		log.Fatal(err)
	}
	DebugLog.SetOutput(DebugLogFileHandle)

	ReassemblyLogFileHandle, err = os.OpenFile(filepath.Join(outpath, "reassembly.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
	if err != nil {
		log.Fatal(err)
	}
	ReassemblyLog.SetOutput(ReassemblyLogFileHandle)
}

// CloseLogFiles closes the logfile handles.
func CloseLogFiles() []error {
	var errs []error

	if ReassemblyLogFileHandle != nil {
		err := ReassemblyLogFileHandle.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if DebugLogFileHandle != nil {
		err := DebugLogFileHandle.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}
