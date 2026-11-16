package aggregate

// MarkSeen atomically records a namespaced key and reports whether it existed.
func (s *Store) MarkSeen(key string) (bool, error) {
	seen := false
	err := s.Do(func(tx *Tx) error {
		_, found, err := tx.Get(key)
		seen = found
		if err != nil || found {
			return err
		}
		return tx.Put(key, []byte{1})
	})
	return seen, err
}
