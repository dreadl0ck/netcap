package defaults

import (
	"runtime"
	"testing"
)

func TestWorkersRespectRuntimeCPUQuota(t *testing.T) {
	old := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(old)
	if CaptureWorkers() != 2 {
		t.Fatal("worker default oversubscribes runtime quota")
	}
}
