package core

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

type failingFragments struct{}

func (failingFragments) Count() int64                       { return 1 }
func (failingFragments) Walk(func(DataFragment) bool) error { return errFragmentFixture }

var errFragmentFixture = errors.New("fixture source unavailable")

func BenchmarkReadSourcePrefixSingleFragment(b *testing.B) {
	source := SliceSource{&StreamData{RawData: make([]byte, 96)}}
	b.ReportAllocs()
	for b.Loop() {
		prefix, err := ReadSourcePrefix(source, 16<<10)
		if err != nil || len(prefix) != 96 {
			b.Fatalf("prefix length %d: %v", len(prefix), err)
		}
	}
}

func TestRestartableFragmentIterationAndErrors(t *testing.T) {
	data := DataFragments{&StreamData{RawData: []byte("first")}, &StreamData{RawData: []byte("second")}}
	c := &ConversationInfo{Source: SliceSource(data)}
	for range 2 {
		n := 0
		for f := range c.Fragments() {
			if string(f.Raw()) != "first" {
				t.Fatal("first item changed")
			}
			n++
			break
		}
		if n != 1 {
			t.Fatal(n)
		}
	}
	n := 0
	for range c.Fragments() {
		n++
	}
	if n != 2 || c.FragmentCount() != 2 {
		t.Fatal(n, c.FragmentCount())
	}
	c.Source = failingFragments{}
	for range c.Fragments() {
	}
	if !errors.Is(c.FragmentError, errFragmentFixture) {
		t.Fatal("source error lost", c.FragmentError)
	}
}

func TestFragmentRangesValidateBoundsAndNestedOffsets(t *testing.T) {
	data := SliceSource{&StreamData{RawData: []byte("zero")}, &StreamData{RawData: []byte("one")}, &StreamData{RawData: []byte("two")}}
	rangeSource := FragmentRange(FragmentRange(data, 1, 2), 1, 1)
	var got []string
	if err := rangeSource.Walk(func(fragment DataFragment) bool { got = append(got, string(fragment.Raw())); return true }); err != nil || !reflect.DeepEqual(got, []string{"two"}) {
		t.Fatal(got, err)
	}
	for _, bounds := range [][2]int64{{-1, 1}, {0, -1}, {4, 0}, {2, 2}, {1, math.MaxInt64}, {math.MaxInt64, 1}} {
		calls := 0
		err := FragmentRange(data, bounds[0], bounds[1]).Walk(func(DataFragment) bool { calls++; return true })
		if err == nil || calls != 0 {
			t.Fatal("invalid source range was consumed", bounds, err, calls)
		}
	}
}

type trackedFragmentSource struct {
	DataFragments
	active *int
}

func (s trackedFragmentSource) Count() int64 { return int64(len(s.DataFragments)) }
func (s trackedFragmentSource) Walk(yield func(DataFragment) bool) error {
	*s.active++
	defer func() { *s.active-- }()
	return SliceSource(s.DataFragments).Walk(yield)
}

func TestMergedSourcePreservesDirectionalOrderAndStopsBorrowers(t *testing.T) {
	fragment := func(name string, at int64) DataFragment {
		return &StreamData{RawData: []byte(name), CaptureInformation: gopacket.CaptureInfo{Timestamp: time.Unix(at, 0)}}
	}
	active := 0
	source := MergedSource{
		Client: trackedFragmentSource{DataFragments{fragment("c5", 5), fragment("c1", 1), fragment("c9", 9)}, &active},
		Server: trackedFragmentSource{DataFragments{fragment("s3", 3), fragment("s5", 5), fragment("s10", 10)}, &active},
	}
	for range 2 {
		var got []string
		if err := source.Walk(func(f DataFragment) bool { got = append(got, string(f.Raw())); return true }); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, []string{"s3", "c5", "c1", "s5", "c9", "s10"}) || source.Count() != 6 || active != 0 {
			t.Fatal(got, active)
		}
	}
	if err := source.Walk(func(DataFragment) bool { return false }); err != nil || active != 0 {
		t.Fatal("stopped source retained borrowers", err, active)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("callback panic lost")
			}
		}()
		_ = source.Walk(func(DataFragment) bool { panic("control") })
	}()
	if active != 0 {
		t.Fatal("panic retained source borrowers", active)
	}
	source.Server = failingFragments{}
	if err := source.Walk(func(DataFragment) bool { return true }); !errors.Is(err, errFragmentFixture) || active != 0 {
		t.Fatal("merge lost source error", err, active)
	}
}
