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

package file

import (
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/dreadl0ck/netcap/decoder"
	decoderconfig "github.com/dreadl0ck/netcap/decoder/config"
	"github.com/dreadl0ck/netcap/types"
)

// Decoder for protocol analysis and writing audit records to disk.
var Decoder = &decoder.AbstractDecoder{
	Type:        types.Type_NC_File,
	Name:        "File",
	Description: "A file that was transferred over the network",
}

// WriteFile writeDeviceProfile writes the profile.
func WriteFile(f *types.File) {
	// File extraction is driven by the protocol decoders, so this is reached
	// whenever a transfer is seen even if the File decoder itself was not
	// selected and has no writer.
	if Decoder.Writer == nil {
		return
	}

	if decoderconfig.Instance.ExportMetrics {
		f.Inc()
	}

	atomic.AddInt64(&Decoder.NumRecordsWritten, 1)

	err := Decoder.Writer.Write(f)
	if err != nil {
		saveFileLog.Error("failed to write File audit record", zap.Error(err))
	}
}

// WriteFileEnhanced writes an enhanced file record with additional fields
// This is an alias to WriteFile for consistency
func WriteFileEnhanced(f *types.File) {
	WriteFile(f)
}
