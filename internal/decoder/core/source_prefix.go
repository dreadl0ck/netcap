package core

func ReadSourcePrefix(source FragmentSource, limit int) ([]byte, error) {
	return readSourcePrefix(source, limit, nil)
}

// ReadBudgetedSourcePrefix reserves the returned capacity. The caller releases
// cap(prefix) credits after consuming it; errors leave no reservation.
func ReadBudgetedSourcePrefix(source FragmentSource, limit int, budget *StateBudget) ([]byte, error) {
	var credit int64
	var transferred bool
	defer func() {
		if !transferred {
			budget.Release(credit)
		}
	}()
	prefix, err := readSourcePrefix(source, limit, func(n int64) error {
		if err := budget.Reserve(n); err != nil {
			return err
		}
		credit = n
		return nil
	})
	if err != nil {
		return nil, err
	}
	transferred = true
	return prefix, nil
}

func readSourcePrefix(source FragmentSource, limit int, reserve func(int64) error) ([]byte, error) {
	if limit <= 0 {
		return nil, nil
	}
	count := source.Count()
	if count == 0 {
		return nil, nil
	}
	var prefix []byte
	var reserveErr error
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
			if reserve != nil {
				if reserveErr = reserve(int64(capacity)); reserveErr != nil {
					return false
				}
			}
			prefix = make([]byte, 0, capacity)
		}
		prefix = append(prefix, raw[:min(len(raw), limit-len(prefix))]...)
		return len(prefix) < limit
	})
	if err == nil {
		err = reserveErr
	}
	return prefix, err
}
