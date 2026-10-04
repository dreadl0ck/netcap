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

// Package cryptoutils provides hashing and random token helpers.
package cryptoutils

import (
	"crypto/md5" //nolint:gosec // MD5 used only for checksums, not security
	"crypto/rand"
	"encoding/base64"
	"io"
)

// MD5Data computes the MD5 digest of the input bytes.
// Note: MD5 is used here only for non-cryptographic checksums (e.g., file integrity).
func MD5Data(input []byte) []byte {
	sum := md5.Sum(input) //nolint:gosec
	return sum[:]
}

// RandomString produces a URL-safe random string of exactly n characters.
// Uses base64url encoding of cryptographically random bytes.
func RandomString(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}

	// base64 expands 3 bytes to 4 chars; compute bytes needed
	byteCount := (n*3)/4 + 1
	buf := make([]byte, byteCount)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", err
	}

	// Encode and truncate to requested length
	result := base64.URLEncoding.EncodeToString(buf)
	return result[:n], nil
}
