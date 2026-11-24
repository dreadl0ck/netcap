// Package exitcode classifies command errors into process exit codes.
package exitcode

// Code returns the exit code for err: 0 for nil, the code of an error that
// carries one (ExitCode() int), 1 if any joined leaf is uncoded or fatal, and
// otherwise the highest code among joined leaves.
func Code(err error) int {
	if err == nil {
		return 0
	}
	if coded, ok := err.(interface{ ExitCode() int }); ok {
		return coded.ExitCode()
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		code := 0
		for _, child := range joined.Unwrap() {
			next := Code(child)
			if next == 1 {
				return 1
			}
			code = max(code, next)
		}
		return code
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if inner := wrapped.Unwrap(); inner != nil {
			return Code(inner)
		}
	}
	return 1
}
