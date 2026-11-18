package webui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/dreadl0ck/netcap/internal/behavior"
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

func behaviorRecordBudget(r *http.Request) inventoryAuditBudget {
	return inventoryAuditBudget{ctx: r.Context(), stored: 64 << 20, bodies: 64 << 20, rows: 10000, frame: 1 << 20}
}

var behaviorRecordSlots = make(chan struct{}, 2)

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
	if r.Context().Err() != nil {
		return
	}
	select {
	case behaviorRecordSlots <- struct{}{}:
		defer func() { <-behaviorRecordSlots }()
	default:
		http.Error(w, "Behavior record queries are busy; retry", http.StatusTooManyRequests)
		return
	}
	budget := behaviorRecordBudget(r)
	reader, err := budget.open(filepath.Join(dir, "Alert.ncap.gz"), types.Type_NC_Alert)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		} else if errors.Is(err, errInventoryAuditLimit) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer reader.Close()
	var selected *types.Alert
	for {
		record, err := budget.next(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			if r.Context().Err() == nil {
				status := http.StatusInternalServerError
				if errors.Is(err, errInventoryAuditLimit) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, err.Error(), status)
			}
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
	matcher := behavior.NewLateralRecordMatcher(evidence, selected.Timestamp)
	for _, name := range []string{"Connection", "SMB"} {
		if err := scanBehaviorRecords(r, dir, name, matcher, &response); err != nil {
			response.Unavailable = append(response.Unavailable, name+": "+err.Error())
		}
	}
	if r.Context().Err() != nil {
		return
	}
	RespondJSON(w, http.StatusOK, response)
}

func scanBehaviorRecords(r *http.Request, dir, name string, matcher behavior.LateralRecordMatcher, response *behaviorRecordsResponse) error {
	want := types.Type_NC_Connection
	if name == "SMB" {
		want = types.Type_NC_SMB
	}
	budget := behaviorRecordBudget(r)
	path := filepath.Join(dir, name+".ncap")
	reader, err := budget.open(path+".gz", want)
	if errors.Is(err, os.ErrNotExist) {
		reader, err = budget.open(path, want)
	}
	if err != nil {
		if errors.Is(err, errInventoryAuditLimit) {
			response.Truncated = true
		}
		return err
	}
	defer reader.Close()
	for index := 0; ; index++ {
		record, err := budget.next(reader)
		if err == io.EOF {
			return nil
		}
		if errors.Is(err, errInventoryAuditLimit) {
			response.Truncated = true
			return err
		}
		if err != nil {
			return err
		}
		response.Scanned++
		if context := matcher.Match(record, index); context != nil {
			if len(response.Records) >= 64 {
				response.Truncated = true
				return nil
			}
			response.Records = append(response.Records, *context)
		}
	}
}
