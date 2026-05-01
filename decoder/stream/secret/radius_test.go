/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package secret

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildRADIUSPacket builds a minimal RADIUS packet with the given code and attributes
func buildRADIUSPacket(code byte, attrs map[byte][]byte) []byte {
	// Header: Code(1) + Identifier(1) + Length(2) + Authenticator(16)
	pkt := make([]byte, 20)
	pkt[0] = code
	pkt[1] = 0x01 // identifier

	// Authenticator (16 bytes of zeros)
	// Already zero-initialized

	// Add attributes
	for attrType, attrValue := range attrs {
		attrLen := byte(2 + len(attrValue))
		pkt = append(pkt, attrType, attrLen)
		pkt = append(pkt, attrValue...)
	}

	// Set length
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))

	return pkt
}

func TestRADIUSHarvester_ValidSecret(t *testing.T) {
	ts := time.Now()

	t.Run("Access-Request with username and encrypted password", func(t *testing.T) {
		attrs := map[byte][]byte{
			radiusAttrUserName:     []byte("bob"),
			radiusAttrUserPassword: make([]byte, 32), // 32 bytes encrypted
		}
		data := buildRADIUSPacket(radiusAccessRequest, attrs)
		result := radiusHarvesterFunc(data, "test-flow", ts)
		if result == nil {
			t.Fatal("Expected credential, got nil")
		}
		if result.User != "bob" {
			t.Errorf("Expected user 'bob', got %q", result.User)
		}
		if result.Password == "" {
			t.Error("Expected non-empty password indicator")
		}
	})

	t.Run("Access-Request with CHAP password", func(t *testing.T) {
		attrs := map[byte][]byte{
			radiusAttrUserName:     []byte("bob"),
			radiusAttrCHAPPassword: make([]byte, 17), // CHAP-ID + 16 bytes
		}
		data := buildRADIUSPacket(radiusAccessRequest, attrs)
		result := radiusHarvesterFunc(data, "test-flow", ts)
		if result == nil {
			t.Fatal("Expected credential, got nil")
		}
		if result.User != "bob" {
			t.Errorf("Expected user 'bob', got %q", result.User)
		}
	})
}

func TestRADIUSHarvester_FalsePositives(t *testing.T) {
	ts := time.Now()

	t.Run("Access-Accept without password is skipped", func(t *testing.T) {
		attrs := map[byte][]byte{
			radiusAttrUserName: []byte("bob"),
		}
		data := buildRADIUSPacket(radiusAccessAccept, attrs)
		result := radiusHarvesterFunc(data, "test-flow", ts)
		if result != nil {
			t.Errorf("Expected nil for Access-Accept without password, got User=%q Password=%q", result.User, result.Password)
		}
	})

	t.Run("Access-Reject without password is skipped", func(t *testing.T) {
		attrs := map[byte][]byte{
			radiusAttrUserName: []byte("bob"),
		}
		data := buildRADIUSPacket(radiusAccessReject, attrs)
		result := radiusHarvesterFunc(data, "test-flow", ts)
		if result != nil {
			t.Errorf("Expected nil for Access-Reject without password, got User=%q", result.User)
		}
	})

	t.Run("anonymous with no password is skipped", func(t *testing.T) {
		attrs := map[byte][]byte{
			radiusAttrUserName: []byte("anonymous"),
		}
		data := buildRADIUSPacket(radiusAccessRequest, attrs)
		result := radiusHarvesterFunc(data, "test-flow", ts)
		if result != nil {
			t.Errorf("Expected nil for anonymous/no-password, got User=%q", result.User)
		}
	})

	t.Run("Access-Request with no username is skipped", func(t *testing.T) {
		attrs := map[byte][]byte{
			radiusAttrUserPassword: make([]byte, 16),
		}
		data := buildRADIUSPacket(radiusAccessRequest, attrs)
		result := radiusHarvesterFunc(data, "test-flow", ts)
		if result != nil {
			t.Errorf("Expected nil for no-username Access-Request, got User=%q", result.User)
		}
	})
}
