package aggregate

const BatchRows = 32
const BatchBytes = 256 << 10

type Row struct {
	Key   string
	Value []byte
}

// NextBatch copies a frozen range before the caller releases Do. Consumers run
// outside Do; mutable ranges must keep Next/Each's per-record visibility.
// One oversized first row is returned to make progress, as with Next.
func (t *Tx) NextBatch(prefix, after string) ([]Row, error) {
	if err := t.flush(); err != nil {
		return nil, err
	}
	query := `SELECT key,value FROM state WHERE key>? AND key<? ORDER BY key LIMIT ?`
	if after == "" {
		after = prefix
		query = `SELECT key,value FROM state WHERE key>=? AND key<? ORDER BY key LIMIT ?`
	}
	statement, err := t.store.statement(query)
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query(after, prefixEnd(prefix), BatchRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batch []Row
	bytes := 0
	for rows.Next() {
		var row Row
		if err := rows.Scan(&row.Key, &row.Value); err != nil {
			return nil, err
		}
		cost := len(row.Key) + len(row.Value) + 64
		if len(batch) > 0 && cost > BatchBytes-bytes {
			break
		}
		batch = append(batch, row)
		bytes += cost
		t.store.health.DiskReads++
		if bytes >= BatchBytes {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}
