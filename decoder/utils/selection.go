package utils

import (
	"strings"

	"github.com/pkg/errors"
)

// SelectDecoders selects a private slice of defaults using globally registered names.
func SelectDecoders[T any](defaults []T, include, exclude string, nameOf func(T) string, invalidDecoder error) ([]T, error) {
	active := append([]T(nil), defaults...)
	in := strings.Split(include, ",")
	// A leading empty name disables the entire include phase, including validation.
	if in[0] != "" {
		inMap := make(map[string]bool)
		for _, name := range in {
			if name != "" {
				if _, ok := AllDecoderNames[name]; !ok {
					return nil, errors.Wrap(invalidDecoder, name)
				}
				inMap[name] = true
			}
		}

		var selection []T
		for _, decoder := range active {
			if inMap[nameOf(decoder)] {
				selection = append(selection, decoder)
			}
		}
		active = selection
	}

	for _, name := range strings.Split(exclude, ",") {
		if name != "" {
			if _, ok := AllDecoderNames[name]; !ok {
				return nil, errors.Wrap(invalidDecoder, name)
			}
			for i, decoder := range active {
				if name == nameOf(decoder) {
					active = append(active[:i], active[i+1:]...)
					break
				}
			}
		}
	}
	return active, nil
}
