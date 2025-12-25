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

// Package cryptoutils implements cryptographic primitives used by netcap
// for secure communication between distributed components.
// It wraps the NaCl box construction for authenticated public-key encryption
// and provides utilities for hashing and random token generation.
package cryptoutils

import (
	"crypto/md5"  //nolint:gosec // MD5 used only for checksums, not security
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// Curve25519 key dimensions used by NaCl box.
const (
	// KeySize represents the byte length of Curve25519 keys.
	KeySize = 32

	// nonceLen is the byte length for XSalsa20 nonces.
	nonceLen = 24
)

// GenerateKeypair produces a fresh Curve25519 key pair suitable for
// use with the NaCl box authenticated encryption scheme.
func GenerateKeypair() (pub, priv *[KeySize]byte, err error) {
	pub, priv, err = box.GenerateKey(rand.Reader)
	return
}

// AsymmetricEncrypt secures plaintext using NaCl box (Curve25519 + XSalsa20 + Poly1305).
// The recipient's public key and sender's private key authenticate the message.
// Output format: [24-byte nonce][ciphertext with 16-byte auth tag]
func AsymmetricEncrypt(message []byte, recipientPub, senderPriv *[KeySize]byte) ([]byte, error) {
	// Allocate space for nonce
	var n [nonceLen]byte

	// Fill nonce with cryptographically secure random bytes
	_, err := io.ReadFull(rand.Reader, n[:])
	if err != nil {
		return nil, err
	}

	// box.Seal appends the encrypted, authenticated message to the nonce
	sealed := box.Seal(n[:], message, &n, recipientPub, senderPriv)
	return sealed, nil
}

// AsymmetricDecrypt reverses AsymmetricEncrypt, verifying authenticity
// and recovering the original plaintext. Returns (nil, false) on failure.
func AsymmetricDecrypt(sealed []byte, senderPub, recipientPriv *[KeySize]byte) ([]byte, bool) {
	// Reject messages too short to contain nonce
	if len(sealed) < nonceLen {
		return nil, false
	}

	// Split nonce from ciphertext
	var n [nonceLen]byte
	copy(n[:], sealed[:nonceLen])
	ciphertext := sealed[nonceLen:]

	// Authenticate and decrypt
	return box.Open(nil, ciphertext, &n, senderPub, recipientPriv)
}

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
