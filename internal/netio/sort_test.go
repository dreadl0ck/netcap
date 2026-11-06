package netio

import (
	"github.com/dreadl0ck/netcap/types"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalSortStableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.ncap")
	h := &types.Header{Type: types.Type_NC_Kerberos, InputSource: "original.pcap"}
	var records []timedRecord
	for i, ts := range []int64{3, 1, 2, 1, 0, 3, 2} {
		records = append(records, &types.Kerberos{Timestamp: ts, ErrorCode: int32(i)})
	}
	if err := writeSortedRun(path, h, records); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0111 != 0 {
		t.Fatal(info, err)
	}
	for _, budget := range []int{1, 100, 1 << 20} {
		out, cleanup, err := sortedAuditFile(path, budget)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Open(out, 4096)
		if err != nil {
			t.Fatal(err)
		}
		gotHeader, err := r.ReadHeader()
		if err != nil || gotHeader.InputSource != h.InputSource {
			t.Fatal(gotHeader, err)
		}
		for _, index := range []int32{4, 1, 3, 2, 6, 0, 5} {
			rec := &types.Kerberos{}
			if err := r.Next(rec); err != nil || rec.ErrorCode != index {
				t.Fatalf("index %d: %v %v", index, rec, err)
			}
		}
		if err := r.Next(&types.Kerberos{}); err != io.EOF {
			t.Fatal(err)
		}
		_ = r.Close()
		cleanup()
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("temporary output survived cleanup")
		}
	}
}

func TestSortRejectsTruncatedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.ncap")
	if err := writeSortedRun(path, &types.Header{Type: types.Type_NC_Kerberos}, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{10, 1})
	_ = f.Close()
	if _, _, err := sortedAuditFile(path, 10); err == nil {
		t.Fatal("truncated audit record silently accepted")
	}
}

func TestAuditFilesHaveNoExecuteBits(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := filepath.Join(t.TempDir(), "audit")
		if existing {
			if err := os.WriteFile(name+".ncap", nil, 0755); err != nil {
				t.Fatal(err)
			}
		}
		f := createFile(name, ".ncap")
		info, err := f.Stat()
		_ = f.Close()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal(info, err)
		}
	}
}
