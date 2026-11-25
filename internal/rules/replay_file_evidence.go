package rules

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dreadl0ck/netcap/types"
)

const (
	maxPendingFileFindings    = 512
	maxPendingFileRecordBytes = 4 << 20
	maxFileMatchExamples      = 32
)

func fileForReplayEvidence(rule *Rule, record types.AuditRecord) *types.File {
	file, ok := record.(*types.File)
	if !ok || file.Timestamp <= 0 || file.SrcIP == "" || file.DstIP == "" || len(file.SrcIP) > 128 || len(file.DstIP) > 128 {
		return nil
	}
	if rule.Threshold > 1 || rule.DistinctField != "" || rule.Sequence != nil || len(rule.DedupeBy) != 0 || len(rule.Actions) != 0 {
		return nil
	}
	return file
}

type fileMatchExample struct {
	Kind        string `json:"kind"`
	SHA256      string `json:"sha256"`
	MD5         string `json:"md5,omitempty"`
	Timestamp   int64  `json:"timestampNs,string"`
	CommunityID string `json:"communityID,omitempty"`
	Length      int64  `json:"length"`
	Complete    bool   `json:"complete"`
}

type fileMatchIdentity struct {
	hash     [sha256.Size]byte
	complete bool
}

type fileFinding struct {
	alert     *types.Alert
	examples  map[fileMatchIdentity]struct{}
	count     uint64
	last      int64
	omitted   uint64
	projected bool
}

func (f *fileFinding) observe(file *types.File) {
	f.count++
	f.last = max(f.last, file.Timestamp)
	var key fileMatchIdentity
	if len(file.GetHashes().GetSHA256()) != 2*sha256.Size {
		f.omitted++
		return
	}
	if _, err := hex.Decode(key.hash[:], []byte(file.GetHashes().GetSHA256())); err != nil {
		f.omitted++
		return
	}
	key.complete = file.IsComplete
	if _, ok := f.examples[key]; ok {
		return
	}
	if len(f.examples) == maxFileMatchExamples {
		f.omitted++
		return
	}
	example := fileMatchExample{
		Kind: "file-match", SHA256: hex.EncodeToString(key.hash[:]),
		Timestamp: file.Timestamp, Length: file.Length, Complete: file.IsComplete,
	}
	var md5 [16]byte
	if value := file.GetHashes().GetMD5(); len(value) == 2*len(md5) {
		if _, err := hex.Decode(md5[:], []byte(value)); err == nil {
			example.MD5 = hex.EncodeToString(md5[:])
		}
	}
	if len(file.CommunityID) <= 128 {
		example.CommunityID = file.CommunityID
	}
	encoded, _ := json.Marshal(example)
	f.alert.Examples = append(f.alert.Examples, string(encoded))
	f.examples[key] = struct{}{}
}

// The replay keeps the first finding pending until its existing dedup window
// closes. Repeated matches can then add evidence before the append-only write.
type replayFileEvidence struct {
	writer  AlertWriter
	window  time.Duration
	reopen  func(alertKey)
	pending map[alertKey]*list.Element
	order   list.List
	bytes   int
}

func (r *replayFileEvidence) observeDuplicate(alert *types.Alert, file *types.File) {
	if elem := r.pending[dedupKey(alert)]; elem != nil {
		finding := elem.Value.(*fileFinding)
		if file.Timestamp >= finding.alert.Timestamp && uint64(file.Timestamp)-uint64(finding.alert.Timestamp) < uint64(r.window) {
			finding.observe(file)
		}
	}
}

func (r *replayFileEvidence) start(alert *types.Alert, file *types.File) (int, error) {
	n := 0
	key := dedupKey(alert)
	if previous := r.pending[key]; previous != nil {
		// An out-of-order replay may start this pair's next window before the
		// front of the queue expires. Commit the previous finding first.
		if err := r.emit(previous, false); err != nil {
			return n, err
		}
		n++
	}
	// Apply the writer's projection before buffering, so a large first
	// record can still retain the hashes of later matches.
	bounded := alert.WithBoundedMatchedRecord()
	size := len(bounded.MatchedRecord)
	if r.pending == nil {
		r.pending = make(map[alertKey]*list.Element)
	}
	for len(r.pending) == maxPendingFileFindings || r.bytes+size > maxPendingFileRecordBytes {
		if err := r.emit(r.order.Front(), true); err != nil {
			return n, err
		}
		n++
	}
	finding := &fileFinding{alert: bounded, examples: make(map[fileMatchIdentity]struct{}), projected: bounded != alert}
	finding.observe(file)
	r.pending[key] = r.order.PushBack(finding)
	r.bytes += size
	return n, nil
}

func (r *replayFileEvidence) flush(at int64, all bool) (int, error) {
	n := 0
	for elem := r.order.Front(); elem != nil; elem = r.order.Front() {
		first := elem.Value.(*fileFinding).alert.Timestamp
		if !all && (at < first || uint64(at)-uint64(first) < uint64(r.window)) {
			break
		}
		if err := r.emit(elem, false); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (r *replayFileEvidence) emit(elem *list.Element, early bool) error {
	finding := elem.Value.(*fileFinding)
	key := dedupKey(finding.alert)
	alert := *finding.alert
	if finding.count > 1 || early || finding.projected {
		alert.Count, alert.FirstSeen, alert.LastSeen = finding.count, alert.Timestamp, finding.last
		wire, _ := json.Marshal([3]string{key.rule, key.src, key.dst})
		alert.AggregateKey = fmt.Sprintf("file:%x", sha256.Sum256(wire))
		if finding.omitted != 0 || early || finding.projected {
			status, _ := json.Marshal(struct {
				Kind      string `json:"kind"`
				Omitted   uint64 `json:"omittedMatches,omitempty"`
				Early     bool   `json:"flushedEarly,omitempty"`
				Projected bool   `json:"matchedRecordProjected,omitempty"`
			}{"file-evidence-limit", finding.omitted, early, finding.projected})
			alert.Examples = append(alert.Examples, string(status))
		}
	} else {
		alert.Examples = nil
	}
	if err := r.writer.WriteAlert(&alert); err != nil {
		return err
	}
	r.bytes -= len(alert.MatchedRecord)
	delete(r.pending, key)
	r.order.Remove(elem)
	if early {
		// A later match must be able to start another segment rather than
		// being suppressed against a finding we can no longer update.
		r.reopen(key)
	}
	return nil
}
