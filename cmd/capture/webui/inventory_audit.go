package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dreadl0ck/netcap/internal/artifactio"
	"github.com/dreadl0ck/netcap/internal/delimited"
	"github.com/dreadl0ck/netcap/types"
	"github.com/gogo/protobuf/proto"
)

var errInventoryAuditLimit = errors.New("inventory audit exceeds page scan limits")

type inventoryAuditBudget struct {
	ctx          context.Context
	stored       int64
	bodies, rows int
	frame        int
}

func openInventoryAuditReader(f *os.File, size int64, ctx context.Context, want types.Type) (*AuditRecordReader, error) {
	r, err := auditRecordReaderFromInput(f, io.NewSectionReader(f, 0, size), strings.HasSuffix(f.Name(), ".gz"), func(in io.Reader) io.Reader {
		return auditContextReader{ctx: ctx, input: in}
	})
	if err != nil {
		return nil, err
	}
	header, err := r.ReadHeader()
	if err == nil && header.Type != want {
		err = fmt.Errorf("unexpected inventory audit type %s, want %s", header.Type, want)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (b *inventoryAuditBudget) open(path string, want types.Type) (*AuditRecordReader, error) {
	var r *AuditRecordReader
	var err error
	if b == nil {
		r, err = NewAuditRecordReader(path)
	} else {
		if err := b.ctx.Err(); err != nil {
			return nil, err
		}
		f, info, err := artifactio.Open(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			return nil, err
		}
		if info.Size() > b.stored {
			f.Close()
			return nil, errInventoryAuditLimit
		}
		b.stored -= info.Size()
		return openInventoryAuditReader(f, info.Size(), b.ctx, want)
	}
	if err != nil {
		return nil, err
	}
	if _, err := r.ReadHeader(); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (b *inventoryAuditBudget) next(r *AuditRecordReader) (proto.Message, error) {
	if b == nil {
		return r.NextRecord()
	}
	raw, err := b.nextRaw(r)
	if err != nil {
		return nil, err
	}
	return r.DecodeRecord(raw)
}

func (b *inventoryAuditBudget) nextRaw(r *AuditRecordReader) ([]byte, error) {
	if b == nil {
		return r.NextRaw()
	}
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}
	limit := b.bodies
	if b.frame > 0 {
		limit = min(limit, b.frame)
	}
	if b.rows == 0 {
		limit = 0
	}
	raw, err := r.delimitedReader.NextWithLimit(uint64(max(1, limit)))
	if errors.Is(err, delimited.ErrRecordLimit) || (err == nil && (b.rows == 0 || len(raw) > limit)) {
		return nil, errInventoryAuditLimit
	}
	if err != nil {
		return nil, err
	}
	b.rows--
	b.bodies -= len(raw)
	return raw, nil
}
