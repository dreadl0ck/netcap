package utils

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	logFilePermission = 0755
)

var (
	ReassemblyLog           = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)
	ReassemblyLogFileHandle *os.File

	DebugLog           = log.New(ioutil.Discard, "", log.LstdFlags|log.Lmicroseconds)
	DebugLogFileHandle *os.File
)

func InitLoggers() {
	var err error
	DebugLogFileHandle, err = os.OpenFile("debug.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
	if err != nil {
		log.Fatal(err)
	}
	DebugLog.SetOutput(DebugLogFileHandle)

	ReassemblyLogFileHandle, err = os.OpenFile("reassembly.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
	if err != nil {
		log.Fatal(err)
	}
	ReassemblyLog.SetOutput(ReassemblyLogFileHandle)
}

// CloseLogFiles closes the logfile handles
func CloseLogFiles() {
	if ReassemblyLogFileHandle != nil {
		if err := ReassemblyLogFileHandle.Close(); err != nil {
			fmt.Println("failed to close reassembly log file handle:", err)
		}
	}
	if DebugLogFileHandle != nil {
		if err := DebugLogFileHandle.Close(); err != nil {
			fmt.Println("failed to close debug log file handle:", err)
		}
	}
}
