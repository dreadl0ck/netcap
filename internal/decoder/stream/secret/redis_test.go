/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package secret

import (
	"testing"
	"time"
)

func TestRedisHarvester_ValidAuth(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		name           string
		data           string
		expectPassword string
		expectUser     string
		expectNil      bool
	}{
		{
			name:           "simple AUTH",
			data:           "AUTH mysecretpassword\r\n",
			expectPassword: "mysecretpassword",
		},
		{
			name:           "RESP protocol AUTH",
			data:           "*2\r\n$4\r\nAUTH\r\n$8\r\npassw0rd\r\n",
			expectPassword: "passw0rd",
		},
		{
			name:           "ACL AUTH with username",
			data:           "AUTH myuser mypassword\r\n",
			expectUser:     "myuser",
			expectPassword: "mypassword",
		},
		{
			name:           "case insensitive",
			data:           "auth secretpass\r\n",
			expectPassword: "secretpass",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := redisHarvesterFunc([]byte(tc.data), "192.0.2.1:12345->192.0.2.2:6379", ts)
			if tc.expectNil {
				if result != nil {
					t.Errorf("Expected nil, got credential with Password=%q", result.Password)
				}
				return
			}
			if result == nil {
				t.Fatal("Expected credential, got nil")
			}
			if result.Password != tc.expectPassword {
				t.Errorf("Expected password %q, got %q", tc.expectPassword, result.Password)
			}
			if tc.expectUser != "" && result.User != tc.expectUser {
				t.Errorf("Expected user %q, got %q", tc.expectUser, result.User)
			}
		})
	}
}

func TestRedisHarvester_FalsePositives(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		name string
		data string
	}{
		{
			name: "TLS keyword",
			data: "AUTH TLS\r\n",
		},
		{
			name: "SSL keyword",
			data: "AUTH SSL\r\n",
		},
		{
			name: "STARTTLS keyword",
			data: "AUTH STARTTLS\r\n",
		},
		{
			name: "no CRLF in data",
			data: "AUTH password",
		},
		{
			name: "AUTH in middle of binary data",
			data: "\x00\x01AUTH something\x00\x02",
		},
		{
			name: "too short",
			data: "AU",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := redisHarvesterFunc([]byte(tc.data), "test-flow", ts)
			if result != nil {
				t.Errorf("Expected nil for false positive %q, got credential with Password=%q", tc.name, result.Password)
			}
		})
	}
}

func TestRedisRequiresProtocolContextOutsideServicePorts(t *testing.T) {
	flow := "192.0.2.1:12345->192.0.2.2:25"
	for _, data := range []string{"EHLO client\r\nAUTH LOGIN\r\n", "AUTH PLAIN dGVzdA==\r\n", "AUTH LOGIN dGVzdA==\r\n", "AUTH arbitrary\r\n", "*2\r\n$4\r\nAUTH\r\n$99999999999999999999999999\r\nx\r\n", "*2\r\n$4\r\nAUTH\r\n$4\r\npassXX"} {
		if redisHarvesterFunc([]byte(data), flow, time.Unix(1, 0)) != nil {
			t.Fatal("unqualified AUTH accepted")
		}
	}
	for _, data := range []string{"AUTH arbitrary\r\n+OK\r\n", "*2\r\n$4\r\nAUTH\r\n$4\r\npass\r\n"} {
		if redisHarvesterFunc([]byte(data), flow, time.Unix(1, 0)) == nil {
			t.Fatal("framed Redis on nonstandard port lost")
		}
	}
}
