package dbs

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func replaceAtomicFile(source, target string) error {
	deadline := time.Now().Add(time.Second)
	for {
		err := os.Rename(source, target)
		// Windows readers can briefly deny replacement while holding the old file.
		if (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION)) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(5 * time.Millisecond)
	}
}
