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

// makeTeamViewerPacket creates a minimal TeamViewer protocol packet with the given command code
func makeTeamViewerPacket(cmdCode uint8) []byte {
	data := make([]byte, 10)
	binary.BigEndian.PutUint16(data[0:2], rdMagicV1) // TeamViewer v1 magic
	data[2] = 0x00                                     // padding
	data[3] = cmdCode                                  // command code
	return data
}

func TestTeamViewerHarvester_SkipsKeepalive(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		name    string
		cmdCode uint8
	}{
		{"PING", 16},
		{"PING_OK", 17},
		{"KEEPALIVE_BEEP", 27},
		{"REQUEST_KEEPALIVE", 28},
		{"KEEPALIVE_REQUEST", 35},
		{"REQUEST_KEEPALIVE_V2", 40},
		{"TIMEOUT", 25},
		{"OK", 36},
		{"FAILED", 37},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := makeTeamViewerPacket(tc.cmdCode)
			result := teamviewerHarvesterFunc(data, "test-flow", ts)
			if result != nil {
				t.Errorf("Expected nil for %s (code %d), got credential with User=%q", tc.name, tc.cmdCode, result.User)
			}
		})
	}
}

func TestTeamViewerHarvester_DetectsAuthEvents(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		name    string
		cmdCode uint8
	}{
		{"AUTH_CHALLENGE", 102},
		{"AUTH_RESPONSE", 103},
		{"AUTH_RESULT", 104},
		{"NEW_MASTER_LOGIN", 45},
		{"NEW_MASTER_LOGIN_ANSWER", 48},
		{"MEETING_AUTHENTICATION", 59},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := makeTeamViewerPacket(tc.cmdCode)
			result := teamviewerHarvesterFunc(data, "test-flow", ts)
			if result == nil {
				t.Errorf("Expected credential for %s (code %d), got nil", tc.name, tc.cmdCode)
			}
		})
	}
}
