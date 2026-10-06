package rules

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gogo/protobuf/proto"

	"github.com/dreadl0ck/netcap/types"
)

var ErrAlertNotReady = errors.New("no complete alert member available")
var ErrAlertCursor = errors.New("alert cursor no longer matches capture history")

type AlertEvent struct {
	Cursor string
	Alert  *types.Alert
}

// AlertTail follows complete gzip members without rescanning history on each poll.
// Legacy first-member records are validated once and streamed with bounded memory.
type AlertTail struct {
	file        *os.File
	path        string
	identity    os.FileInfo
	generation  string
	offset      int64
	firstEnd    int64
	legacyCount uint64
	legacyIndex uint64
	legacy      *bufio.Reader
	legacyGzip  *gzip.Reader
}

func OpenAlertTail(path, cursor string) (*AlertTail, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	tail := &AlertTail{file: file, path: path}
	success := false
	defer func() {
		if !success {
			_ = tail.Close()
		}
	}()
	tail.identity, err = file.Stat()
	if err != nil {
		return nil, err
	}
	section := io.NewSectionReader(file, 0, tail.identity.Size())
	raw := bufio.NewReader(section)
	gz, err := gzip.NewReader(raw)
	if err != nil {
		return nil, incompleteAlert(err)
	}
	gz.Multistream(false)
	reader := bufio.NewReader(gz)
	data, err := readAlertFrame(reader)
	if err != nil {
		_ = gz.Close()
		return nil, incompleteAlert(err)
	}
	var header types.Header
	if err := proto.Unmarshal(data, &header); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if header.Type != types.Type_NC_Alert {
		_ = gz.Close()
		return nil, errors.New("expected Alert audit header")
	}
	for {
		data, err := readAlertFrame(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = gz.Close()
			return nil, incompleteAlert(err)
		}
		var alert types.Alert
		if err := proto.Unmarshal(data, &alert); err != nil {
			_ = gz.Close()
			return nil, err
		}
		tail.legacyCount++
	}
	_ = gz.Close()
	position, err := section.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	tail.firstEnd = position - int64(raw.Buffered())
	hash := sha256.New()
	_, _ = io.WriteString(hash, path+"\x00")
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, tail.firstEnd)); err != nil {
		return nil, err
	}
	tail.generation = hex.EncodeToString(hash.Sum(nil))
	tail.offset = tail.firstEnd
	var skip uint64
	if cursor != "" {
		parts := strings.Split(cursor, ":")
		if len(parts) != 3 || len(cursor) > 160 || parts[0] != tail.generation {
			return nil, ErrAlertCursor
		}
		offset, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || offset < 0 || offset > tail.identity.Size() || (offset > 0 && offset < tail.firstEnd) {
			return nil, ErrAlertCursor
		}
		skip, err = strconv.ParseUint(parts[2], 10, 64)
		if err != nil || (offset != 0 && skip != 0) || (offset == 0 && (skip == 0 || skip > tail.legacyCount)) {
			return nil, ErrAlertCursor
		}
		if offset != 0 {
			tail.offset = offset
			tail.legacyCount = 0
		}
	}
	if tail.legacyCount > skip {
		gz, err := gzip.NewReader(io.NewSectionReader(file, 0, tail.firstEnd))
		if err != nil {
			return nil, err
		}
		tail.legacyGzip, tail.legacy = gz, bufio.NewReader(gz)
		for i := uint64(0); i <= skip; i++ {
			if _, err := readAlertFrame(tail.legacy); err != nil {
				return nil, err
			}
		}
		tail.legacyIndex = skip
	}
	success = true
	return tail, nil
}

func readAlertFrame(reader *bufio.Reader) ([]byte, error) {
	size, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, err
	}
	if size > maxAlertRecordSize {
		return nil, fmt.Errorf("alert record exceeds %d bytes", maxAlertRecordSize)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	return data, nil
}

func incompleteAlert(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrAlertNotReady
	}
	return err
}

func (t *AlertTail) Next() (AlertEvent, error) {
	current, err := os.Stat(t.path)
	if err != nil || !os.SameFile(t.identity, current) || current.Size() < t.offset {
		return AlertEvent{}, ErrAlertCursor
	}
	if t.legacy != nil && t.legacyIndex < t.legacyCount {
		data, err := readAlertFrame(t.legacy)
		if err != nil {
			return AlertEvent{}, err
		}
		alert := new(types.Alert)
		if err := proto.Unmarshal(data, alert); err != nil {
			return AlertEvent{}, err
		}
		t.legacyIndex++
		cursor := fmt.Sprintf("%s:0:%d", t.generation, t.legacyIndex)
		if t.legacyIndex == t.legacyCount {
			cursor = fmt.Sprintf("%s:%d:0", t.generation, t.firstEnd)
		}
		return AlertEvent{Cursor: cursor, Alert: alert}, nil
	}
	if t.legacyGzip != nil {
		_ = t.legacyGzip.Close()
		t.legacyGzip, t.legacy = nil, nil
	}
	if current.Size() == t.offset {
		return AlertEvent{}, ErrAlertNotReady
	}
	section := io.NewSectionReader(t.file, t.offset, current.Size()-t.offset)
	raw := bufio.NewReader(section)
	gz, err := gzip.NewReader(raw)
	if err != nil {
		return AlertEvent{}, incompleteAlert(err)
	}
	defer gz.Close()
	gz.Multistream(false)
	reader := bufio.NewReader(gz)
	data, err := readAlertFrame(reader)
	if err != nil {
		return AlertEvent{}, incompleteAlert(err)
	}
	if _, err := readAlertFrame(reader); err != io.EOF {
		if err == nil {
			return AlertEvent{}, errors.New("expected one alert per appended member")
		}
		return AlertEvent{}, incompleteAlert(err)
	}
	alert := new(types.Alert)
	if err := proto.Unmarshal(data, alert); err != nil {
		return AlertEvent{}, err
	}
	position, err := section.Seek(0, io.SeekCurrent)
	if err != nil {
		return AlertEvent{}, err
	}
	t.offset += position - int64(raw.Buffered())
	return AlertEvent{Cursor: fmt.Sprintf("%s:%d:0", t.generation, t.offset), Alert: alert}, nil
}

func (t *AlertTail) Close() error {
	var err error
	if t.legacyGzip != nil {
		err = t.legacyGzip.Close()
	}
	return errors.Join(err, t.file.Close())
}
