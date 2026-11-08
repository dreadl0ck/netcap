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

package collector

import (
	"context"
	"os"
)

func openPcapNG(path string) (*scopedNgReader, *os.File, error) {
	r, f, err := openCaptureInput(path, true)
	if err != nil {
		return nil, nil, err
	}
	return r.(*scopedNgReader), f, nil
}

func countPacketsNG(path string) (int64, error) {
	return countCaptureInput(context.Background(), path, true)
}

// CollectPcapNG shares the bounded count/process policy with CollectPcap.
func (c *Collector) CollectPcapNG(path string) error {
	return c.collectCaptureInput(path, true)
}
