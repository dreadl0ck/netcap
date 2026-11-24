package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// MaxMatchedRecordBytes bounds the evidence copy in one alert. Page readers
// refuse frames above 1 MiB, so one oversized HTTP body used to fail every
// alert view of a session.
const MaxMatchedRecordBytes = 256 << 10

// WithBoundedMatchedRecord returns a copy whose oversized matched record is
// replaced by its identity; the full record stays in its own audit and its
// SHA-256 in the alert. The receiver is not modified.
func (a *Alert) WithBoundedMatchedRecord() *Alert {
	if len(a.MatchedRecord) <= MaxMatchedRecordBytes {
		return a
	}
	trimmed := *a
	if trimmed.MatchedRecordSHA256 == "" {
		digest := sha256.Sum256([]byte(a.MatchedRecord))
		trimmed.MatchedRecordSHA256 = hex.EncodeToString(digest[:])
	}
	projection, _ := json.Marshal(struct {
		Timestamp            int64  `json:"Timestamp"`
		Type                 string `json:"Type"`
		SrcIP                string `json:"SrcIP"`
		DstIP                string `json:"DstIP"`
		MatchedRecordOmitted bool   `json:"MatchedRecordOmitted"`
		MatchedRecordBytes   int    `json:"MatchedRecordBytes"`
		MatchedRecordSHA256  string `json:"MatchedRecordSHA256"`
	}{a.Timestamp, a.RecordType, a.SrcIP, a.DstIP, true, len(a.MatchedRecord), trimmed.MatchedRecordSHA256})
	trimmed.MatchedRecord = string(projection)
	return &trimmed
}
