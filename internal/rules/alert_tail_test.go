package rules

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
)

func TestAlertTailAppendAndResume(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	if err := w.WriteAlert(&types.Alert{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	tail, err := OpenAlertTail(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	first, err := tail.Next()
	if err != nil || first.Alert.Name != "first" {
		t.Fatalf("first = %+v, %v", first, err)
	}
	if _, err := tail.Next(); !errors.Is(err, ErrAlertNotReady) {
		t.Fatalf("empty tail = %v", err)
	}
	if err := w.WriteAlert(&types.Alert{Name: "second"}); err != nil {
		t.Fatal(err)
	}
	second, err := tail.Next()
	if err != nil || second.Alert.Name != "second" {
		t.Fatalf("second = %+v, %v", second, err)
	}
	resumed, err := OpenAlertTail(path, first.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	event, err := resumed.Next()
	if err != nil || event.Cursor != second.Cursor || event.Alert.Name != "second" {
		t.Fatalf("resume = %+v, %v", event, err)
	}
}

func TestAlertTailLegacyHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Alert.ncap.gz")
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	d := delimited.NewWriter(gz)
	_ = d.PutProto(&types.Header{Type: types.Type_NC_Alert})
	_ = d.PutProto(&types.Alert{Name: "legacy-first"})
	_ = d.PutProto(&types.Alert{Name: "legacy-second"})
	_ = gz.Close()
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	tail, err := OpenAlertTail(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	first, err := tail.Next()
	if err != nil || first.Alert.Name != "legacy-first" {
		t.Fatal(err)
	}
	resumed, err := OpenAlertTail(path, first.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	second, err := resumed.Next()
	if err != nil || second.Alert.Name != "legacy-second" {
		t.Fatalf("legacy resume = %+v, %v", second, err)
	}
	if err := openAlertWriter(t, dir).WriteAlert(&types.Alert{Name: "new"}); err != nil {
		t.Fatal(err)
	}
	event, err := resumed.Next()
	if err != nil || event.Alert.Name != "new" {
		t.Fatalf("legacy append = %+v, %v", event, err)
	}
}

func TestAlertTailWaitsForCompleteMember(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	if err := w.WriteAlert(&types.Alert{Name: "committed"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	tail, err := OpenAlertTail(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	if _, err := tail.Next(); err != nil {
		t.Fatal(err)
	}
	var member bytes.Buffer
	gz := gzip.NewWriter(&member)
	_ = delimited.NewWriter(gz).PutProto(&types.Alert{Name: "later"})
	_ = gz.Close()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data := member.Bytes()
	if _, err := file.Write(data[:len(data)-4]); err != nil {
		t.Fatal(err)
	}
	if _, err := tail.Next(); !errors.Is(err, ErrAlertNotReady) {
		t.Fatalf("partial member emitted: %v", err)
	}
	if _, err := file.Write(data[len(data)-4:]); err != nil {
		t.Fatal(err)
	}
	event, err := tail.Next()
	if err != nil || event.Alert.Name != "later" {
		t.Fatalf("completed member = %+v, %v", event, err)
	}
}

func TestAlertTailDetectsHistoryReplacement(t *testing.T) {
	dir := t.TempDir()
	w := openAlertWriter(t, dir)
	if err := w.WriteAlert(&types.Alert{Name: "first"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "Alert.ncap.gz")
	tail, err := OpenAlertTail(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer tail.Close()
	event, err := tail.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAlertTail(path, "wrong:0:0"); !errors.Is(err, ErrAlertCursor) {
		t.Fatalf("invalid cursor = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, alertFixture(t, types.Type_NC_Alert), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := tail.Next(); !errors.Is(err, ErrAlertCursor) {
		t.Fatalf("replacement = %v", err)
	}
	if opened, err := OpenAlertTail(path, event.Cursor); !errors.Is(err, ErrAlertCursor) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("stale cursor = %v", err)
	}
}
