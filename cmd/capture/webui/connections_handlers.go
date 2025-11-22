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

package webui

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/dreadl0ck/netcap/types"
)

// ConnectionSummary represents aggregated information for a single connection
type ConnectionSummary struct {
	TimestampFirst      int64    `json:"timestampFirst"`
	TimestampLast       int64    `json:"timestampLast"`
	LinkProto           string   `json:"linkProto"`
	NetworkProto        string   `json:"networkProto"`
	TransportProto      string   `json:"transportProto"`
	ApplicationProto    string   `json:"applicationProto"`
	SrcMAC              string   `json:"srcMAC"`
	DstMAC              string   `json:"dstMAC"`
	SrcIP               string   `json:"srcIP"`
	SrcPort             string   `json:"srcPort"`
	DstIP               string   `json:"dstIP"`
	DstPort             string   `json:"dstPort"`
	TotalSize           int32    `json:"totalSize"`
	AppPayloadSize      int32    `json:"appPayloadSize"`
	NumPackets          int32    `json:"numPackets"`
	Duration            int64    `json:"duration"`
	BytesClientToServer int64    `json:"bytesClientToServer"`
	BytesServerToClient int64    `json:"bytesServerToClient"`
	NumFINFlags         int32    `json:"numFINFlags"`
	NumRSTFlags         int32    `json:"numRSTFlags"`
	NumACKFlags         int32    `json:"numACKFlags"`
	NumSYNFlags         int32    `json:"numSYNFlags"`
	NumURGFlags         int32    `json:"numURGFlags"`
	NumECEFlags         int32    `json:"numECEFlags"`
	NumPSHFlags         int32    `json:"numPSHFlags"`
	NumCWRFlags         int32    `json:"numCWRFlags"`
	NumNSFlags          int32    `json:"numNSFlags"`
	MeanWindowSize      int32    `json:"meanWindowSize"`
	Applications        []string `json:"applications"`
}

// ConnectionsResponse contains the list of connections
type ConnectionsResponse struct {
	Connections []ConnectionSummary `json:"connections"`
	TotalCount  int                 `json:"totalCount"`
}

// handleConnections returns a list of all connections
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	outDir := s.outDir

	// In service mode, use the current session's output directory
	if s.isServiceMode && s.currentSession != "" && s.sessionManager != nil {
		if session, ok := s.sessionManager.GetSession(s.currentSession); ok {
			outDir = session.OutputDir
		}
	}
	s.mu.RUnlock()

	if outDir == "" {
		http.Error(w, "No output directory set", http.StatusServiceUnavailable)
		return
	}

	connections, err := readConnections(outDir)
	if err != nil {
		log.Printf("[WebUI] Failed to read connections: %v", err)
		http.Error(w, "Failed to read connections", http.StatusInternalServerError)
		return
	}

	response := ConnectionsResponse{
		Connections: connections,
		TotalCount:  len(connections),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// readConnections reads and aggregates Connection data from the output directory
func readConnections(outDir string) ([]ConnectionSummary, error) {
	filePath := filepath.Join(outDir, "Connection.ncap.gz")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("[WebUI] Connection file not found: %s", filePath)
		return []ConnectionSummary{}, nil
	}

	// Read Connection records
	reader, err := NewAuditRecordReader(filePath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// Read header
	_, err = reader.ReadHeader()
	if err != nil {
		return nil, err
	}

	connections := make([]ConnectionSummary, 0)

	// Read all records
	for {
		record, err := reader.NextRecord()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("[WebUI] Error reading Connection record: %v", err)
			continue
		}

		// Type assert to Connection
		conn, ok := record.(*types.Connection)
		if !ok {
			continue
		}

		connections = append(connections, ConnectionSummary{
			TimestampFirst:      conn.TimestampFirst,
			TimestampLast:       conn.TimestampLast,
			LinkProto:           conn.LinkProto,
			NetworkProto:        conn.NetworkProto,
			TransportProto:      conn.TransportProto,
			ApplicationProto:    conn.ApplicationProto,
			SrcMAC:              conn.SrcMAC,
			DstMAC:              conn.DstMAC,
			SrcIP:               conn.SrcIP,
			SrcPort:             conn.SrcPort,
			DstIP:               conn.DstIP,
			DstPort:             conn.DstPort,
			TotalSize:           conn.TotalSize,
			AppPayloadSize:      conn.AppPayloadSize,
			NumPackets:          conn.NumPackets,
			Duration:            conn.Duration,
			BytesClientToServer: conn.BytesClientToServer,
			BytesServerToClient: conn.BytesServerToClient,
			NumFINFlags:         conn.NumFINFlags,
			NumRSTFlags:         conn.NumRSTFlags,
			NumACKFlags:         conn.NumACKFlags,
			NumSYNFlags:         conn.NumSYNFlags,
			NumURGFlags:         conn.NumURGFlags,
			NumECEFlags:         conn.NumECEFlags,
			NumPSHFlags:         conn.NumPSHFlags,
			NumCWRFlags:         conn.NumCWRFlags,
			NumNSFlags:          conn.NumNSFlags,
			MeanWindowSize:      conn.MeanWindowSize,
			Applications:        conn.Applications,
		})
	}

	// Sort by total size descending (or by timestamp - could be configurable)
	sort.Slice(connections, func(i, j int) bool {
		return connections[i].TotalSize > connections[j].TotalSize
	})

	return connections, nil
}

