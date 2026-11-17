package core

import "fmt"

type RangedFragmentSource interface {
	FragmentSource
	WalkRange(start, count int64, yield func(DataFragment) bool) error
}

func CheckFragmentRange(size, start, count int64) error {
	if start < 0 || count < 0 || start > size || count > size-start {
		return fmt.Errorf("fragment range outside source")
	}
	return nil
}

func (s SliceSource) WalkRange(start, count int64, yield func(DataFragment) bool) error {
	if err := CheckFragmentRange(s.Count(), start, count); err != nil {
		return err
	}
	return SliceSource(s[start : start+count]).Walk(yield)
}

type fragmentRange struct {
	source       RangedFragmentSource
	start, count int64
}

func FragmentRange(source RangedFragmentSource, start, count int64) RangedFragmentSource {
	return fragmentRange{source, start, count}
}
func (s fragmentRange) Count() int64 { return s.count }
func (s fragmentRange) Walk(yield func(DataFragment) bool) error {
	return s.WalkRange(0, s.count, yield)
}
func (s fragmentRange) WalkRange(start, count int64, yield func(DataFragment) bool) error {
	if err := CheckFragmentRange(s.source.Count(), s.start, s.count); err != nil {
		return err
	}
	if err := CheckFragmentRange(s.count, start, count); err != nil {
		return err
	}
	return s.source.WalkRange(s.start+start, count, yield)
}
