package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/expr-lang/expr"
)

type captureStatusError int

func (e captureStatusError) Error() string { return "qualified capture status" }
func (e captureStatusError) ExitCode() int { return int(e) }

func TestCommandExitCodePreservesLeafErrors(t *testing.T) {
	_, syntaxError := expr.Compile("Method = POST")
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0}, {errors.New("failure"), 1}, {syntaxError, 1}, {fmt.Errorf("compile audit filter: %w", syntaxError), 1},
		{captureStatusError(2), 2}, {fmt.Errorf("capture: %w", captureStatusError(3)), 3},
		{errors.Join(captureStatusError(2), errors.New("storage failure")), 1},
	} {
		if got := commandExitCode(tc.err); got != tc.want {
			t.Fatalf("%v: exit=%d want=%d", tc.err, got, tc.want)
		}
	}
}
