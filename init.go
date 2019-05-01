// +build darwin,linux

package netcap

import (
	"fmt"
	"syscall"
)

/*
 *	Init
 */

func init() {

	// get system block size for use as the buffer size of the buffered Writers
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		fmt.Println("statfs syscall failed. setting blocksize to", blockSizeDefault)
		BlockSize = blockSizeDefault
	}

	// set block size
	BlockSize = int(stat.Bsize)
}
