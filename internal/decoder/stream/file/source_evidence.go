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
	if ok, err := markedSourceEvidence(conv, evidence); err != nil || ok {
		if err == nil {
			conv.Source = evidence
		}
		return err
	}
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

// Reads the same facts from the boundary index. Observation order is the merged
// walk order, which the index preserves only when one direction carries them.
func markedSourceEvidence(conv *core.ConversationInfo, evidence *sourceFileEvidence) (bool, error) {
	merged, ok := conv.Source.(core.MergedSource)
	if !ok {
		return false, nil
	}
	client, clientRanged := merged.Client.(core.RangedFragmentSource)
	server, serverRanged := merged.Server.(core.RangedFragmentSource)
	if !clientRanged || !serverRanged {
		return false, nil
	}
	var observed [2]bool
	result := sourceFileEvidence{}
	for side, source := range []core.RangedFragmentSource{client, server} {
		marks, ok := core.SourceMarks(source)
		if !ok {
			return false, nil
		}
		for _, mark := range marks {
			data, err := core.MarkedFragment(source, mark.Index)
			if err != nil {
				return false, err
			}
			if data == nil {
				continue
			}
			if data.SkippedBytes < 0 {
				result.unknown = true
			} else {
				result.missing += int64(data.SkippedBytes)
			}
			if data.TCPObservation != "" {
				observed[side] = true
				if !slices.Contains(result.transport, data.TCPObservation) {
					result.transport = append(result.transport, data.TCPObservation)
				}
			}
		}
	}
	if observed[0] && observed[1] {
		return false, nil
	}
	evidence.unknown, evidence.missing, evidence.transport = result.unknown, result.missing, result.transport
	return true, nil
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
