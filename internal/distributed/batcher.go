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

package distributed

import (
	"time"

	"github.com/dreadl0ck/netcap/types"
)

// batchOverhead is headroom for the Batch envelope around Data in a frame.
const batchOverhead = 64

// MaxRecordSize is the largest single record a batch can carry within DefaultMaxFrame.
const MaxRecordSize = DefaultMaxFrame - batchOverhead

// BatcherConfig configures RunBatcher.
type BatcherConfig struct {
	Type             types.Type
	MaxBytes         int           // flush when Data would exceed this; clamped to MaxRecordSize
	FlushInterval    time.Duration // flush a non-empty batch at least this often; 0 disables
	ContainsPayloads bool
	Emit             func(*types.Batch)
	OnOversize       func(size int) // called for a record too large to ever send
}

// RunBatcher reads length-delimited records from ch and emits batches until ch
// is closed, then emits what is left. A record larger than MaxBytes is sent
// in a batch of its own; only one larger than MaxRecordSize is dropped.
func RunBatcher(ch <-chan []byte, cfg BatcherConfig) {
	maxBytes := cfg.MaxBytes
	if maxBytes <= 0 || maxBytes > MaxRecordSize {
		maxBytes = MaxRecordSize
	}

	var (
		data []byte
		tick <-chan time.Time
	)

	if cfg.FlushInterval > 0 {
		t := time.NewTicker(cfg.FlushInterval)
		defer t.Stop()
		tick = t.C
	}

	emit := func() {
		if len(data) == 0 {
			return
		}

		cfg.Emit(&types.Batch{
			MessageType:      cfg.Type,
			TotalSize:        int32(len(data)),
			Data:             data,
			ContainsPayloads: cfg.ContainsPayloads,
		})
		data = nil
	}

	for {
		select {
		case rec, ok := <-ch:
			if !ok {
				emit()

				return
			}

			if len(rec) > MaxRecordSize {
				if cfg.OnOversize != nil {
					cfg.OnOversize(len(rec))
				}

				continue
			}

			if len(data) > 0 && len(data)+len(rec) > maxBytes {
				emit()
			}

			data = append(data, rec...)

			if len(data) >= maxBytes {
				emit()
			}
		case <-tick:
			emit()
		}
	}
}
