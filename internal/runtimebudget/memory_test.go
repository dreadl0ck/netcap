package runtimebudget

import (
	"math"
	"os"
	"testing"
)

func TestAutomaticLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    map[string]string
		explicit bool
		current  int64
		want     int64
	}{
		{name: "v2 container", files: map[string]string{"/sys/fs/cgroup/memory.max": "4294967296\n"}, want: 3 << 30},
		{name: "v1 container", files: map[string]string{"/sys/fs/cgroup/memory/memory.limit_in_bytes": "4294967296\n"}, want: 3 << 30},
		{name: "parent limit", files: map[string]string{"/proc/self/cgroup": "0::/parent/child\n", "/sys/fs/cgroup/memory.max": "max", "/sys/fs/cgroup/parent/child/memory.max": "max", "/sys/fs/cgroup/parent/memory.max": "2147483648"}, want: 1536 << 20},
		{name: "v1 parent", files: map[string]string{"/proc/self/cgroup": "5:cpu:/other\n6:memory,freezer:/parent/child\n", "/sys/fs/cgroup/memory/parent/memory.limit_in_bytes": "2147483648"}, want: 1536 << 20},
		{name: "smallest ancestor", files: map[string]string{"/proc/self/cgroup": "0::/parent/child\n", "/sys/fs/cgroup/memory.max": "4294967296", "/sys/fs/cgroup/parent/child/memory.max": "2147483648"}, want: 1536 << 20},
		{name: "unlimited", files: map[string]string{"/sys/fs/cgroup/memory.max": "max", "/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712"}},
		{name: "unreadable"},
		{name: "malformed", files: map[string]string{"/sys/fs/cgroup/memory.max": "-1", "/sys/fs/cgroup/memory/memory.limit_in_bytes": "invalid"}},
		{name: "environment wins", files: map[string]string{"/sys/fs/cgroup/memory.max": "4294967296"}, explicit: true},
		{name: "runtime wins", files: map[string]string{"/sys/fs/cgroup/memory.max": "4294967296"}, current: 1 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := tc.current
			if current == 0 {
				current = math.MaxInt64
			}
			read := func(path string) ([]byte, error) {
				if data, ok := tc.files[path]; ok {
					return []byte(data), nil
				}
				return nil, os.ErrNotExist
			}
			if got := automaticLimit(read, tc.explicit, current); got != tc.want {
				t.Fatalf("limit=%d, want %d", got, tc.want)
			}
		})
	}
}
