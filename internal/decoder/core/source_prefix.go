package core

func ReadSourcePrefix(source FragmentSource, limit int) ([]byte, error) {
	if limit <= 0 || source.Count() == 0 {
		return nil, nil
	}
	prefix := make([]byte, 0, limit)
	err := source.Walk(func(fragment DataFragment) bool {
		if fragment == nil {
			return true
		}
		if data, ok := fragment.(*StreamData); ok && len(prefix) > 0 && (data.SkippedBytes != 0 || data.DiscardedBytes > 0) {
			return false
		}
		prefix = append(prefix, fragment.Raw()[:min(len(fragment.Raw()), limit-len(prefix))]...)
		return len(prefix) < limit
	})
	return prefix, err
}
