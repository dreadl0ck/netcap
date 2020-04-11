/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package encoder

import (
	"log"
	"os"

	"github.com/dreadl0ck/gopacket/reassembly"
)

var (
	c Config
	
	reassemblyLog = log.New(nil, "", log.LstdFlags)
	reassemblyLogFileHandle *os.File

	debugLog = log.New(nil, "", log.LstdFlags)
	debugLogFileHandle *os.File
)

const (
	directoryPermission = 0755
	logFilePermission = 0755
)

// SetConfig can be used to set a configuration for the package
func SetConfig(cfg Config) {
	c = cfg
	fsmOptions = reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: c.AllowMissingInit,
	}
	
	// setup loggers
	if c.Debug {
		var err error
		debugLogFileHandle, err = os.OpenFile("debug.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
		if err != nil {
			log.Fatal(err)
		}
		debugLog.SetOutput(debugLogFileHandle)

		reassemblyLogFileHandle, err = os.OpenFile("reassembly.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, logFilePermission)
		if err != nil {
			log.Fatal(err)
		}
		reassemblyLog.SetOutput(reassemblyLogFileHandle)

		pop3Debug = true
	}
}

// Config contains configuration parameters
// for the encoders
type Config struct {
	Buffer             bool
	Compression        bool
	CSV                bool
	IncludeEncoders    string
	ExcludeEncoders    string
	Out                string
	WriteChan          bool
	Source             string
	Version            string
	IncludePayloads    bool
	Export             bool
	AddContext         bool
	MemBufferSize      int
	FlushEvery         int
	NoDefrag           bool
	Checksum           bool
	NoOptCheck         bool
	IgnoreFSMerr       bool
	AllowMissingInit   bool
	Debug              bool
	HexDump            bool
	WaitForConnections bool
	WriteIncomplete    bool
	MemProfile         string
	ConnFlushInterval  int
	ConnTimeOut        int
	FlowFlushInterval  int
	FlowTimeOut        int
}
