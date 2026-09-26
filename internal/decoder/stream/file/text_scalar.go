//go:build !goexperiment.simd

package file

func isTextFile(data []byte) bool {
	return isTextFileScalar(data)
}
