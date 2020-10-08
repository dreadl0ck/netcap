package stream

import (
	"go.uber.org/zap"
	"log"
	"os"
)

var (
	streamLog *zap.Logger

	reassemblyLog *zap.Logger
	// hold a reference to the file handle so we can dump summary data tables into it.
	reassemblyLogFileHandle *os.File

	// used for colored debug logging
	serviceLog *log.Logger
	pop3Log    *log.Logger
	smtpLog    *log.Logger
)

// SetStreamLogger sets the general decoder logger for the decoder package.
func SetStreamLogger(lg *zap.Logger) {
	streamLog = lg
}

// SetReassemblyLogger sets the general decoder logger for the decoder package.
func SetReassemblyLogger(lg *zap.Logger) {
	reassemblyLog = lg
}

// SetServiceLogger sets the network service logger for the decoder package.
func SetServiceLogger(lg *log.Logger) {
	serviceLog = lg
}

// SetPOP3Logger sets the pop3 logger for the decoder package.
func SetPOP3Logger(lg *log.Logger) {
	pop3Log = lg
}

// SetSMTPLogger sets the pop3 logger for the decoder package.
func SetSMTPLogger(lg *log.Logger) {
	smtpLog = lg
}
