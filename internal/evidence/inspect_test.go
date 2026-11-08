package evidence

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestInspectionPCAPNGAndGzipInterfacesOrderingAndLimits(t *testing.T) {
	var source bytes.Buffer
	for section := 0; section < 2; section++ {
		intf := pcapgo.DefaultNgInterface
		intf.LinkType = layers.LinkTypeEthernet
		intf.SnapLength = 128
		w, err := pcapgo.NewNgWriterInterface(&source, intf, pcapgo.DefaultNgWriterOptions)
		if err != nil {
			t.Fatal(err)
		}
		raw := intf
		raw.LinkType = layers.LinkTypeRaw
		if _, err = w.AddInterface(raw); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			at := int64(1700000000000000003 - int64(section*2+i))
			if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(0, at), InterfaceIndex: i, CaptureLength: 20, Length: 40}, bytes.Repeat([]byte{1}, 20)); err != nil {
				t.Fatal(err)
			}
		}
		if err = w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	for _, compressed := range []bool{false, true} {
		data := source.Bytes()
		if compressed {
			var b bytes.Buffer
			z := gzip.NewWriter(&b)
			if _, err := z.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			data = b.Bytes()
		}
		path := filepath.Join(t.TempDir(), "capture")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := InspectCapture(context.Background(), path, 10, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if got.SourceSHA256 != hex.EncodeToString(hash[:]) || got.Packets != 4 || got.CapturedBytes != 80 || got.WireBytes != 160 || got.TruncatedPackets != 4 || !got.OutOfOrder || len(got.Interfaces) != 4 || got.FirstNs != "1700000000000000000" || got.LastNs != "1700000000000000003" {
			t.Fatalf("inspection %+v", got)
		}
		if compressed && got.Compression != "gzip" {
			t.Fatal("gzip not identified")
		}
		if _, err = InspectCapture(context.Background(), path, 1, 1<<20); err == nil {
			t.Fatal("packet bound ignored")
		}
		if _, err = InspectCapture(context.Background(), path, 10, 1); err == nil {
			t.Fatal("byte bound ignored")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err = InspectCapture(ctx, path, 10, 1<<20); err == nil {
			t.Fatal("cancellation ignored")
		}
		link := filepath.Join(t.TempDir(), "link")
		if err = os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err = InspectCapture(context.Background(), link, 10, 1<<20); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}
