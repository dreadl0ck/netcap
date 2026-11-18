package core

import "errors"

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
	capacity := limit
	if resident, ok := source.(SliceSource); ok && count > 1 {
		capacity = residentPrefixSize(resident, limit)
	}
	err := source.Walk(func(fragment DataFragment) bool {
		if fragment == nil {
			return true
		}
		if len(prefix) > 0 && breaksSourcePrefix(fragment) {
			return false
		}
		raw := fragment.Raw()
		if len(raw) > 0 && prefix == nil {
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
		n := min(len(raw), limit-len(prefix))
		if n > cap(prefix)-len(prefix) {
			reserveErr = errors.New("fragment source changed during prefix read")
			return false
		}
		prefix = append(prefix, raw[:n]...)
		return len(prefix) < limit
	})
	if err == nil {
		err = reserveErr
	}
	return prefix, err
}

func residentPrefixSize(source SliceSource, limit int) int {
	size := 0
	for _, fragment := range source {
		if fragment == nil {
			continue
		}
		if size > 0 && breaksSourcePrefix(fragment) {
			break
		}
		size += min(len(fragment.Raw()), limit-size)
		if size == limit {
			break
		}
	}
	return size
}

func breaksSourcePrefix(fragment DataFragment) bool {
	data, ok := fragment.(*StreamData)
	return ok && (data.SkippedBytes != 0 || data.DiscardedBytes > 0)
}
