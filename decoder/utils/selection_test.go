package utils

import (
	"errors"
	"reflect"
	"testing"

	pkgerrors "github.com/pkg/errors"
)

func TestSelectDecoders(t *testing.T) {
	previous := AllDecoderNames
	AllDecoderNames = map[string]struct{}{"A": {}, "B": {}, "C": {}, "Other": {}}
	t.Cleanup(func() { AllDecoderNames = previous })
	sentinel := errors.New("invalid test decoder")
	defaults := []string{"A", "B", "A", "C"}
	for _, tt := range []struct {
		name             string
		defaults         []string
		include, exclude string
		want             []string
		errName          string
	}{
		{"defaults", defaults, "", "", defaults, ""},
		{"nil defaults", nil, "", "", nil, ""},
		{"empty defaults", []string{}, "", "", nil, ""},
		{"nil include", nil, "A", "", nil, ""},
		{"nil exclude", nil, "", "A", nil, ""},
		{"empty tokens", defaults, ",,", ",,", defaults, ""},
		{"leading empty disables include", defaults, ",B", "", defaults, ""},
		{"leading empty skips validation", defaults, ",Missing", "B", []string{"A", "A", "C"}, ""},
		{"include order and duplicates", defaults, "C,A,A", "", []string{"A", "A", "C"}, ""},
		{"include empty tokens", defaults, "B,,C,", "", []string{"B", "C"}, ""},
		{"global include absent locally", defaults, "Other", "", nil, ""},
		{"global exclude absent locally", defaults, "", "Other", defaults, ""},
		{"exclude absent from selection", defaults, "B", "A", []string{"B"}, ""},
		{"exclude first duplicate", defaults, "", "A", []string{"B", "A", "C"}, ""},
		{"exclude repeated duplicate", defaults, "", "A,A,A", []string{"B", "C"}, ""},
		{"exclude empty tokens", defaults, "", ",A,,C,", []string{"B", "A"}, ""},
		{"include then exclude", defaults, "C,A", "A", []string{"A", "C"}, ""},
		{"exclude all is nonnil", defaults, "", "A,B,A,C", []string{}, ""},
		{"exclude selected all is nonnil", defaults, "B", "B,B", []string{}, ""},
		{"no selection remains nil", defaults, "Other", "A", nil, ""},
		{"unregistered defaults allowed", []string{"Local"}, "", "", []string{"Local"}, ""},
		{"unregistered local include", []string{"Local"}, "Local", "", nil, "Local"},
		{"unregistered local exclude", []string{"Local"}, "", "Local", nil, "Local"},
		{"unknown include", defaults, "Missing", "", nil, "Missing"},
		{"unknown exclude", defaults, "", "Missing", nil, "Missing"},
		{"first include error", defaults, "A,Missing,Unknown", "BadExclude", nil, "Missing"},
		{"first exclude error after deletion", defaults, "", "A,Missing,Unknown", nil, "Missing"},
		{"validate excludes after empty selection", defaults, "Other", "Missing", nil, "Missing"},
		{"disabled include still validates exclude", defaults, ",Missing", "Unknown", nil, "Unknown"},
		{"validate include without defaults", nil, "Missing", "", nil, "Missing"},
		{"validate exclude without defaults", nil, "", "Missing", nil, "Missing"},
		{"include no trim", defaults, " A", "", nil, " A"},
		{"exclude no trim", defaults, "", "A ", nil, "A "},
		{"include no case folding", defaults, "a", "", nil, "a"},
		{"exclude no case folding", defaults, "", "b", nil, "b"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Spare capacity catches writes beyond the input slice's length too.
			backing := append(append([]string{}, tt.defaults...), "guard", "guard")
			input := backing[:len(tt.defaults)]
			if tt.defaults == nil {
				input = nil
			}
			before := append([]string(nil), backing...)
			got, err := SelectDecoders(input, tt.include, tt.exclude, func(s string) string { return s }, sentinel)
			if tt.errName != "" {
				if !errors.Is(err, sentinel) || pkgerrors.Cause(err) != sentinel || err.Error() != tt.errName+": "+sentinel.Error() {
					t.Fatalf("error = %v, want wrapped sentinel for %q", err, tt.errName)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("selection = %#v, want %#v", got, tt.want)
			}
			if len(got) > 0 {
				got[0] = "changed"
			}
			got = append(got, "appended")
			if !reflect.DeepEqual(backing, before) {
				t.Fatalf("defaults backing array changed: %v, want %v", backing, before)
			}
		})
	}
}

func TestSelectDecodersConcreteTypes(t *testing.T) {
	previous := AllDecoderNames
	AllDecoderNames = map[string]struct{}{"A": {}, "B": {}}
	t.Cleanup(func() { AllDecoderNames = previous })
	type decoder struct {
		name string
		data []int
	}
	a, b, duplicate := decoder{"A", []int{1}}, decoder{"B", []int{2}}, decoder{"A", []int{3}}
	sentinel := errors.New("invalid")
	values, err := SelectDecoders([]decoder{a, b, duplicate}, "B,A", "A", func(d decoder) string { return d.name }, sentinel)
	if err != nil || !reflect.DeepEqual(values, []decoder{b, duplicate}) {
		t.Fatalf("value selection = %v, %v", values, err)
	}
	pointers, err := SelectDecoders([]*decoder{&a, &b, &duplicate}, "B,A", "A", func(d *decoder) string { return d.name }, sentinel)
	if err != nil || !reflect.DeepEqual(pointers, []*decoder{&b, &duplicate}) {
		t.Fatalf("pointer selection = %v, %v", pointers, err)
	}
	// Only the slice is copied; selected decoder objects retain their identity.
	pointers[0].data[0] = 42
	if b.data[0] != 42 {
		t.Fatal("selected decoder was deep-copied")
	}
}
