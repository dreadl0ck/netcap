package mpegts

import (
	"encoding/hex"
	"testing"
)

func TestSPSMetadataMatchesEncoderFixtures(t *testing.T) {
	// Single 1280x720 color frames encoded by FFmpeg's libx264 and libx265.
	h264, _ := hex.DecodeString("6764001facd9405005bb011000000300100000030320f1831960")
	h265, _ := hex.DecodeString("42010101600000030090000003000003005da00280802d165959a4932bc05a020000030002000003003210")
	info, err := h264SPS(h264[1:])
	if err != nil || info.Width != 1280 || info.Height != 720 || info.Profile != 100 || info.Level != 31 {
		t.Fatal(info, err)
	}
	info, err = h265SPS(h265[2:])
	if err != nil || info.Width != 1280 || info.Height != 720 || info.Profile != 1 || info.Level != 93 {
		t.Fatal(info, err)
	}
}

func FuzzSPSBounds(f *testing.F) {
	f.Add([]byte{100, 0, 31})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		_, _ = h264SPS(data)
		_, _ = h265SPS(data)
	})
}
