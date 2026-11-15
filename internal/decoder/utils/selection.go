package utils

import (
	"strings"

	"github.com/pkg/errors"
)

// SelectDecoders selects a private slice of defaults using globally registered names.
func SelectDecoders[T any](defaults []T, include, exclude string, nameOf func(T) string, invalidDecoder error) ([]T, error) {
	active := append([]T(nil), defaults...)
	in, err := NormalizeDecoderList(include, invalidDecoder)
	if err != nil {
		return nil, err
	}
	out, err := NormalizeDecoderList(exclude, invalidDecoder)
	if err != nil {
		return nil, err
	}
	if len(in) != 0 {
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

	for _, name := range out {
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

func NormalizeDecoderList(list string, invalidDecoder error) ([]string, error) {
	canonical := make(map[string]string, len(AllDecoderNames))
	for name := range AllDecoderNames {
		canonical[strings.ToLower(name)] = name
	}
	var names []string
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, ok := canonical[strings.ToLower(item)]
		if !ok {
			return nil, errors.Wrap(invalidDecoder, item)
		}
		names = append(names, name)
	}
	return names, nil
}
