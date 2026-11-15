package core

import (
	"errors"
	"testing"
)

type failingFragments struct{}

func (failingFragments) Count() int64                       { return 1 }
func (failingFragments) Walk(func(DataFragment) bool) error { return errFragmentFixture }

var errFragmentFixture = errors.New("fixture source unavailable")

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
