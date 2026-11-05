package defaults

import "runtime"

func CaptureWorkers() int { return max(1, runtime.GOMAXPROCS(0)) }
