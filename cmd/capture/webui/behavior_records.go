package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/behavior"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

type behaviorRecordsResponse struct {
	Schema        int                      `json:"schema"`
	AlertID       string                   `json:"alertId"`
	Records       []behavior.RecordContext `json:"records"`
	Unavailable   []string                 `json:"unavailable"`
	Scanned       int                      `json:"scanned"`
	Truncated     bool                     `json:"truncated"`
	Qualification string                   `json:"qualification"`
}

func (s *Server) handleBehaviorRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir, ok := s.behaviorDirectory(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("alertId")
	if len(id) == 0 || len(id) > 512 {
		http.Error(w, "alert ID is required", http.StatusBadRequest)
		return
	}
	reader, err := NewAuditRecordReader(filepath.Join(dir, "Alert.ncap.gz"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer reader.Close()
	reader.delimitedReader = delimited.NewReaderWithLimit(reader.reader, 1<<20)
	header, err := reader.ReadHeader()
	if err != nil || header.Type != types.Type_NC_Alert {
		http.Error(w, "invalid Alert audit header", http.StatusInternalServerError)
		return
	}
	var selected *types.Alert
	for count, bytes := 0, 0; count < 10000 && bytes < 64<<20; count++ {
		if r.Context().Err() != nil {
			return
		}
		raw, err := reader.NextRaw()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		bytes += len(raw)
		if bytes > 64<<20 {
			break
		}
		record, err := reader.DecodeRecord(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		alert := record.(*types.Alert)
		if alertResponse(alert).AlertID == id {
			selected = alert
			break
		}
	}
	if selected == nil {
		http.Error(w, "alert not found within bounded retained history", http.StatusNotFound)
		return
	}
	var evidence behavior.Evidence
	if err := json.Unmarshal([]byte(selected.MatchedRecord), &evidence); err != nil {
		http.Error(w, "invalid behavioral evidence", http.StatusBadRequest)
		return
	}
	response := behaviorRecordsResponse{Schema: 1, AlertID: id, Records: []behavior.RecordContext{}, Unavailable: []string{}, Qualification: "Tuple/time candidates only: Connection and SMB audit records omit sensor/interface/VLAN. Capture lag measures record timestamps, not emission latency. Original alert evidence is unchanged."}
	for _, name := range []string{"Connection", "SMB"} {
		if err := scanBehaviorRecords(r, dir, name, selected.Timestamp, evidence, &response); err != nil {
			response.Unavailable = append(response.Unavailable, name+": "+err.Error())
		}
	}
	RespondJSON(w, http.StatusOK, response)
}

func scanBehaviorRecords(r *http.Request, dir, name string, timestamp int64, evidence behavior.Evidence, response *behaviorRecordsResponse) error {
	path := filepath.Join(dir, name+".ncap.gz")
	reader, err := NewAuditRecordReader(path)
	if errors.Is(err, os.ErrNotExist) {
		reader, err = NewAuditRecordReader(filepath.Join(dir, name+".ncap"))
	}
	if err != nil {
		return err
	}
	defer reader.Close()
	reader.delimitedReader = delimited.NewReaderWithLimit(reader.reader, 1<<20)
	header, err := reader.ReadHeader()
	if err != nil {
		return err
	}
	want := types.Type_NC_Connection
	if name == "SMB" {
		want = types.Type_NC_SMB
	}
	if header.Type != want {
		return fmt.Errorf("audit header type mismatch")
	}
	bytes := 0
	for index := 0; index < 10000 && bytes < 64<<20; index++ {
		if err := r.Context().Err(); err != nil {
			return err
		}
		raw, err := reader.NextRaw()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		bytes += len(raw)
		if bytes > 64<<20 {
			response.Truncated = true
			return nil
		}
		response.Scanned++
		record, err := reader.DecodeRecord(raw)
		if err != nil {
			return err
		}
		if context := behavior.MatchLateralRecord(evidence, timestamp, record, index); context != nil {
			if len(response.Records) >= 64 {
				response.Truncated = true
				return nil
			}
			response.Records = append(response.Records, *context)
		}
	}
	response.Truncated = true
	return nil
}
