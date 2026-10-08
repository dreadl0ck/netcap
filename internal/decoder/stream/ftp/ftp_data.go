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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package ftp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dreadl0ck/netcap/internal/decoder/config"
	"github.com/dreadl0ck/netcap/internal/decoder/core"
	"github.com/dreadl0ck/netcap/internal/decoder/stream/file"
	"github.com/dreadl0ck/netcap/internal/reassembly"
)

const maxPendingBytes = 64 << 20
const maxPendingStreams = 4096
const maxPendingTransfers = 4096

type dataTransfer struct {
	ControlID, ControlCommunityID, ClientIP, ServerIP, IP, Command, Filename string
	Port                                                                     int32
	Passive, Accepted, Complete                                              bool
	Start, End                                                               int64
}
type pendingData struct {
	conv        core.ConversationInfo
	data        [2][]byte
	first, last int64
}
type DataAssociation struct {
	ControlKey         string `json:"controlKey"`
	DataKey            string `json:"dataKey"`
	StartNs            int64  `json:"startNs,string"`
	EndNs              int64  `json:"endNs,string"`
	SHA256             string `json:"sha256"`
	ControlCommunityID string `json:"controlCommunityId"`
	DataCommunityID    string `json:"dataCommunityId"`
	Command            string `json:"command"`
	Filename           string `json:"filename"`
	CompleteReply      bool   `json:"completeReply"`
}
type DataHealth struct {
	Version              int               `json:"version"`
	Status               string            `json:"status"`
	PendingBytes         int               `json:"peakRetainedBytes"`
	Candidates           int               `json:"candidates"`
	Rejected             int               `json:"rejectedByBudget"`
	Ambiguous            int               `json:"ambiguous"`
	Unmatched            int               `json:"unmatched"`
	UnmatchedTransfers   int               `json:"unmatchedTransfers"`
	UnsupportedEndpoints int               `json:"unsupportedEndpoints"`
	Failed               int               `json:"extractionErrors"`
	Associations         []DataAssociation `json:"associations"`
}

var dataState struct {
	sync.Mutex
	enabled   bool
	bytes     int
	streams   []pendingData
	transfers []dataTransfer
	health    DataHealth
}

func initConnectionTracker() {
	dataState.Lock()
	defer dataState.Unlock()
	dataState.enabled = true
	dataState.bytes = 0
	dataState.streams = nil
	dataState.transfers = nil
	dataState.health = DataHealth{Version: 1, Status: "done", Associations: []DataAssociation{}}
}

// ObserveDataConversation owns bounded copies until all control readers have
// finished. Capture time, never goroutine arrival order, determines association.
func ObserveDataConversation(c *core.ConversationInfo) {
	dataState.Lock()
	defer dataState.Unlock()
	if !dataState.enabled || !file.IsProtocolEnabled("FTP") || config.Instance.FileStorage == "" || !c.TCPHandshakeComplete {
		return
	}
	size := 0
	sizes := [2]int{}
	for _, f := range c.Data {
		size += len(f.Raw())
		d := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			d = 1
		}
		sizes[d] += len(f.Raw())
	}
	if size == 0 {
		return
	}
	if len(dataState.streams) >= maxPendingStreams || size > maxPendingBytes-dataState.bytes || len(c.Data) > 65536 {
		dataState.health.Rejected++
		dataState.health.Status = "partial"
		return
	}
	p := pendingData{conv: *c}
	p.conv.Data = nil
	p.conv.ClientData = nil
	p.conv.ServerData = nil
	p.data[0] = make([]byte, 0, sizes[0])
	p.data[1] = make([]byte, 0, sizes[1])
	missing := [2]int{}
	unknown := [2]bool{}
	for _, f := range c.Data {
		d := 0
		if f.Direction() == reassembly.TCPDirServerToClient {
			d = 1
		}
		p.data[d] = append(p.data[d], f.Raw()...)
		ci := f.CaptureInfo()
		if f.Context() != nil {
			ci = f.Context().GetCaptureInfo()
		}
		ts := ci.Timestamp.UnixNano()
		if len(f.Raw()) > 0 {
			if p.first == 0 || ts < p.first {
				p.first = ts
			}
			if ts > p.last {
				p.last = ts
			}
		}
		if s, ok := f.(*core.StreamData); ok && s.SkippedBytes != 0 {
			if s.SkippedBytes < 0 {
				unknown[d] = true
			} else {
				missing[d] += s.SkippedBytes
			}
		}
	}
	for d := range 2 {
		dir := reassembly.TCPDirClientToServer
		if d == 1 {
			dir = reassembly.TCPDirServerToClient
		}
		if unknown[d] {
			p.conv.Data = append(p.conv.Data, &core.StreamData{Dir: dir, SkippedBytes: -1})
		}
		if missing[d] > 0 {
			p.conv.Data = append(p.conv.Data, &core.StreamData{Dir: dir, SkippedBytes: missing[d]})
		}
	}
	dataState.bytes += size
	dataState.health.PendingBytes = dataState.bytes
	dataState.health.Candidates++
	dataState.streams = append(dataState.streams, p)
}

func registerTransfer(t dataTransfer) {
	dataState.Lock()
	defer dataState.Unlock()
	if !dataState.enabled || !t.Accepted {
		return
	}
	// Third-party PORT/PASV endpoints require external NAT/bounce evidence.
	if t.Passive && t.IP != t.ServerIP || !t.Passive && t.IP != t.ClientIP {
		dataState.health.UnsupportedEndpoints++
		dataState.health.Status = "partial"
		return
	}
	if len(dataState.transfers) >= maxPendingTransfers || len(t.Filename) > 4096 {
		dataState.health.Rejected++
		dataState.health.Status = "partial"
		return
	}
	t.Filename = strings.Clone(t.Filename)
	dataState.transfers = append(dataState.transfers, t)
}

func matchesTransfer(t dataTransfer, p pendingData) bool {
	if p.first < t.Start || p.last > t.End {
		return false
	}
	if t.Passive {
		return p.conv.ClientIP == t.ClientIP && p.conv.ServerIP == t.ServerIP && p.conv.ServerPort == t.Port
	}
	return p.conv.ClientIP == t.ServerIP && p.conv.ServerIP == t.ClientIP && p.conv.ServerPort == t.Port
}

// FinalizeDataConnections runs after TCP readers drain and before File closes.
// Ambiguous windows are refused rather than choosing the first worker to arrive.
func FinalizeDataConnections() error {
	dataState.Lock()
	defer dataState.Unlock()
	if !dataState.enabled {
		return nil
	}
	dataState.enabled = false
	defer func() { dataState.streams = nil; dataState.transfers = nil; dataState.bytes = 0 }()
	owners := make([]int, len(dataState.streams))
	matches := make([]int, len(dataState.streams))
	counts := make([]int, len(dataState.transfers))
	for i, p := range dataState.streams {
		for j, t := range dataState.transfers {
			if matchesTransfer(t, p) {
				owners[i] = j
				matches[i]++
				counts[j]++
			}
		}
	}
	var failure error
	for _, count := range counts {
		if count == 0 {
			dataState.health.UnmatchedTransfers++
			dataState.health.Status = "partial"
		}
	}
	for i, p := range dataState.streams {
		if matches[i] == 0 {
			dataState.health.Unmatched++
			continue
		}
		if matches[i] != 1 || counts[owners[i]] != 1 {
			dataState.health.Ambiguous++
			dataState.health.Status = "partial"
			continue
		}
		t := dataState.transfers[owners[i]]
		direction := 0
		if (t.Command == "RETR") == t.Passive {
			direction = 1
		}
		if len(p.data[direction]) == 0 {
			dataState.health.Unmatched++
			dataState.health.UnmatchedTransfers++
			dataState.health.Status = "partial"
			continue
		}
		flowDirection := "client_to_server"
		if direction == 1 {
			flowDirection = "server_to_client"
		}
		var incomplete error
		if !t.Complete {
			incomplete = fmt.Errorf("FTP transfer lacks a successful completion reply")
		}
		if err := file.SaveFileEnhanced(&p.conv, "FTP "+t.Command, filepath.Base(t.Filename), incomplete, p.data[direction], nil, t.ServerIP, "", 0, "", flowDirection, "FTP"); err != nil {
			dataState.health.Status = "partial"
			dataState.health.Failed++
			if failure == nil {
				failure = err
			}
			continue
		}
		dataState.health.Associations = append(dataState.health.Associations, DataAssociation{ControlKey: t.ControlID, DataKey: p.conv.Ident, StartNs: p.first, EndNs: p.last, SHA256: fmt.Sprintf("%x", sha256.Sum256(p.data[direction])), ControlCommunityID: t.ControlCommunityID, DataCommunityID: p.conv.CommunityID, Command: t.Command, Filename: t.Filename, CompleteReply: t.Complete})
	}
	if config.Instance.Out == "" {
		return failure
	}
	b, err := json.MarshalIndent(dataState.health, "", "  ")
	if err != nil {
		return err
	}
	return errors.Join(failure, os.WriteFile(filepath.Join(config.Instance.Out, "FTPDataHealth.json"), b, 0600))
}
