package file

import (
	"slices"

	"github.com/dreadl0ck/netcap/internal/decoder/core"
)

type sourceFileEvidence struct {
	core.FragmentSource
	missing   int64
	unknown   bool
	transport []string
}

// PrepareSourceEvidence snapshots immutable transport-run qualifications once.
func PrepareSourceEvidence(conv *core.ConversationInfo) error {
	if conv.Source == nil {
		return nil
	}
	if _, ok := conv.Source.(*sourceFileEvidence); ok {
		return nil
	}
	evidence := &sourceFileEvidence{FragmentSource: conv.Source}
	for fragment := range conv.Fragments() {
		if data, ok := fragment.(*core.StreamData); ok {
			if data.SkippedBytes < 0 {
				evidence.unknown = true
			} else {
				evidence.missing += int64(data.SkippedBytes)
			}
			if data.TCPObservation != "" && !slices.Contains(evidence.transport, data.TCPObservation) {
				evidence.transport = append(evidence.transport, data.TCPObservation)
			}
		}
	}
	if conv.FragmentError != nil {
		return conv.FragmentError
	}
	conv.Source = evidence
	return nil
}

func transportQualifications(conv *core.ConversationInfo) []string {
	var qualifications []string
	if evidence, ok := conv.Source.(*sourceFileEvidence); ok {
		for _, value := range evidence.transport {
			qualifications = append(qualifications, "transport-"+value)
		}
		return qualifications
	}
	for fragment := range conv.Fragments() {
		if data, ok := fragment.(*core.StreamData); ok && data.TCPObservation != "" {
			value := "transport-" + data.TCPObservation
			if !slices.Contains(qualifications, value) {
				qualifications = append(qualifications, value)
			}
		}
	}
	return qualifications
}
