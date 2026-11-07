//go:build !coraza

package waf

import "errors"

func newInspectionEngine(c Config) (inspectionEngine, error) {
	if c.CorazaCRS {
		return nil, errors.New("corazaCRS requires a build with -tags coraza")
	}
	return nil, nil
}
