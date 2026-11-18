package core

func ReadSourcePrefix(source FragmentSource, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	count := source.Count()
	if count == 0 {
		return nil, nil
	}
	var prefix []byte
	err := source.Walk(func(fragment DataFragment) bool {
		if fragment == nil {
			return true
		}
		if data, ok := fragment.(*StreamData); ok && len(prefix) > 0 && (data.SkippedBytes != 0 || data.DiscardedBytes > 0) {
			return false
		}
		raw := fragment.Raw()
		if len(raw) > 0 && prefix == nil {
			capacity := limit
			if count == 1 {
				capacity = min(limit, len(raw))
			}
			prefix = make([]byte, 0, capacity)
		}
		prefix = append(prefix, raw[:min(len(raw), limit-len(prefix))]...)
		return len(prefix) < limit
	})
	return prefix, err
}
