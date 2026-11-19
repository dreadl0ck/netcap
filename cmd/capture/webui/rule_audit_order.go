package webui

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/dreadl0ck/netcap/internal/netio"
	"github.com/dreadl0ck/netcap/internal/rules"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

const (
	ruleOrderMemoryBytes = 4 << 20
	ruleOrderMaxBytes    = 2 << 30
	ruleOrderMaxRows     = 1 << 20
)

type ruleOrderRow struct {
	time, offset int64
	size         int
	digest       [sha256.Size]byte
}

func scanOrderedRuleAudit(dir, auditType string, stop, shutdown <-chan struct{}, visit func(types.AuditRecord) error) (int, error) {
	var rows []ruleOrderRow
	var memory []byte
	var file *os.File
	var size int64
	defer func() {
		if file != nil {
			file.Close()
			os.Remove(file.Name())
		}
	}()
	_, err := scanRuleAudit(dir, auditType, stop, shutdown, func(record types.AuditRecord) error {
		message, ok := record.(proto.Message)
		if !ok {
			return fmt.Errorf("audit record is not a protobuf message")
		}
		if len(rows) == ruleOrderMaxRows || int64(proto.Size(message)) > ruleOrderMaxBytes-size {
			return fmt.Errorf("rule replay ordering budget exceeded")
		}
		wire, err := rules.MarshalReplayRecord(message)
		if err != nil {
			return err
		}
		if int64(len(wire)) > ruleOrderMaxBytes-size {
			return fmt.Errorf("rule replay ordering budget exceeded")
		}
		if file == nil && size+int64(len(wire)) > ruleOrderMemoryBytes {
			file, err = os.CreateTemp("", "netcap-rule-order-*")
			if err != nil {
				return err
			}
			if _, err := file.Write(memory); err != nil {
				return err
			}
			memory = nil
		}
		if file != nil {
			if _, err := file.Write(wire); err != nil {
				return err
			}
		} else {
			memory = append(memory, wire...)
		}
		rows = append(rows, ruleOrderRow{record.Time(), size, len(wire), sha256.Sum256(wire)})
		size += int64(len(wire))
		return nil
	})
	if err != nil {
		return 0, err
	}
	slices.SortFunc(rows, func(a, b ruleOrderRow) int {
		if order := cmp.Compare(a.time, b.time); order != 0 {
			return order
		}
		return bytes.Compare(a.digest[:], b.digest[:])
	})
	var input io.ReaderAt = bytes.NewReader(memory)
	if file != nil {
		input = file
	}
	typ := types.Type(types.Type_value["NC_"+strings.TrimPrefix(auditType, "NC_")])
	var wire []byte
	for i, row := range rows {
		if ruleReplayCanceled(stop, shutdown) {
			return i, errAnalysisStopping
		}
		wire = slices.Grow(wire[:0], row.size)[:row.size]
		if len(wire) != 0 {
			if _, err := input.ReadAt(wire, row.offset); err != nil {
				return i, err
			}
		}
		message := netio.InitRecord(typ)
		record, ok := message.(types.AuditRecord)
		if !ok {
			return i, fmt.Errorf("unsupported audit type %s", typ)
		}
		if err := proto.Unmarshal(wire, message); err != nil {
			return i, err
		}
		if err := visit(record); err != nil {
			return i + 1, err
		}
	}
	return len(rows), nil
}
