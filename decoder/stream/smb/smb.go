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

package smb

import (
	"bytes"

	"github.com/dreadl0ck/netcap/decoder"
	"github.com/dreadl0ck/netcap/decoder/core"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	logging "github.com/dreadl0ck/netcap/logger"
	"github.com/dreadl0ck/netcap/types"
	"go.uber.org/zap"
)

var smbLog = zap.NewNop()

// SMB protocol constants
const (
	// SMB1 header signature
	SMB1Signature = "\xFFSMB"
	// SMB2/3 header signature  
	SMB2Signature = "\xFESMB"
)

// Decoder for SMB protocol analysis
var Decoder = &decoder.StreamDecoder{
	Type:        types.Type_NC_SMB,
	Name:        "SMB",
	Description: "Server Message Block protocol - Windows file sharing",
	PostInit: func(sd *decoder.StreamDecoder) error {
		var err error
		smbLog, _, err = logging.InitZapLogger(
			decoderconfig.Instance.Out,
			"smb",
			decoderconfig.Instance.Debug,
		)
		if err != nil {
			return err
		}
		// Start file handle cleanup
		startSMBCleanup()
		return nil
	},
	CanDecode: func(client, server []byte) bool {
		// Check for SMB1 or SMB2/3 signature
		return bytes.Contains(server, []byte(SMB1Signature)) || 
			   bytes.Contains(server, []byte(SMB2Signature)) ||
			   bytes.Contains(client, []byte(SMB1Signature)) ||
			   bytes.Contains(client, []byte(SMB2Signature))
	},
	DeInit: func(sd *decoder.StreamDecoder) error {
		return smbLog.Sync()
	},
	Factory: &smbReader{},
	Typ:     core.TCP,
}

