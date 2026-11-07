package collector

import "testing"

func TestCaptureInputDistinguishesProtocolEvidenceFromFramingLoss(t *testing.T) {
	malformed := CaptureInputReport{ReachedEOF: true, ProcessedPackets: 1, DecodeErrors: 1}
	if err := malformed.result(); err != nil || malformed.Status != "complete" || malformed.DecodeErrors != 1 {
		t.Fatalf("fully captured malformed protocol became unread input: %+v %v", malformed, err)
	}
	for _, report := range []CaptureInputReport{
		{ReachedEOF: true, ProcessedPackets: 1, LinkErrors: 1},
		{ProcessedPackets: 1, ReadErrors: 1},
		{ReachedEOF: true, ProcessedPackets: 1, Unsupported: 1},
	} {
		if err := report.result(); err == nil || report.Status == "complete" {
			t.Fatalf("input coverage loss became success: %+v", report)
		}
	}
}
