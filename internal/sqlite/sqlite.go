package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/dreadl0ck/netcap/defaults"
	netcapio "github.com/dreadl0ck/netcap/io"
	"github.com/dreadl0ck/netcap/types"
)

const newline = "\n"

// DumpConfig contains all settings for writing audit records to
// an SQLite database.
type DumpConfig struct {
	Paths         []string
	Output        string
	MemBufferSize int
	Selection     string
	Debug         bool
}

func Dump(ctx context.Context, w *os.File, c DumpConfig) error {
	if len(c.Paths) > 1 {
		return errors.New("multiple files not yet supported")
	}

	p := c.Paths[0]
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("failed statting file %q: %w", p, err)
	}

	if !fi.IsDir() {
		return fmt.Errorf("%q is not a directory", p)
	}

	db, err := sql.Open("sqlite", c.Output)
	if err != nil {
		return fmt.Errorf("failed opening SQLite database %q: %w", c.Output, err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			_, _ = w.WriteString(fmt.Sprintf("failed to close database: %v\n", err))
		}
	}()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed starting database transaction: %w", err)
	}

	entries, err := os.ReadDir(p)
	if err != nil {
		return fmt.Errorf("failed reading directory %q: %w", p, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != defaults.FileExtension && filepath.Ext(entry.Name()) != ".gz") {
			continue // skip directories and files that don't look like audit record files
		}

		fp := filepath.Join(p, entry.Name())
		r, err := netcapio.Open(fp, c.MemBufferSize)
		if err != nil {
			return fmt.Errorf("failed to open audit record file: %w", err)
		}

		header, err := r.ReadHeader()
		if err != nil {
			return fmt.Errorf("failed reading record file header: %w", err)
		}

		var (
			record           = netcapio.InitRecord(header.Type)
			isFirstIteration = true
		)

		types.Select(record, "") // with multiple tables, selection can fail; TODO: add support for selection?
		types.UTC = true         // always use UTC

		for {
			err = r.Next(record)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			} else if err != nil {
				return fmt.Errorf("failed to read next audit record: %w", err)
			}

			if p, ok := record.(types.SQLCapableAuditRecord); ok {
				if isFirstIteration {
					if c.Debug {
						_, _ = w.WriteString(p.SQLTable())
						_, _ = w.WriteString(newline)
					}

					if _, err = tx.ExecContext(ctx, p.SQLTable()); err != nil {
						return fmt.Errorf("failed creating table: %w", err)
					}
				}

				query, values := p.SQLInsert()
				if c.Debug {
					_, _ = w.WriteString(fmt.Sprintf("%s, (%s)", query, join(values, ",")))
					_, _ = w.WriteString(newline)
				}

				if _, err = tx.ExecContext(ctx, query, values...); err != nil {
					return fmt.Errorf("failed inserting audit record: %w", err)
				}
			} else {
				_, _ = w.WriteString(fmt.Sprintf("skipped processing %q containing %q audit records; dumping to SQLite not yet supported for this audit record type", fp, header.Type.String()))
				_, _ = w.WriteString(newline)

				// exit from the inner loop; continues with next audit record file
				break
			}

			isFirstIteration = false
		}

	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func join(values []any, sep string) string {
	if len(values) == 0 {
		return ""
	}

	if len(values) == 1 {
		return fmt.Sprintf("%v", values[0])
	}

	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("%v", values[0]))
	for _, s := range values[1:] {
		buffer.WriteString(fmt.Sprintf("%s%v", sep, s))
	}

	return buffer.String()
}
