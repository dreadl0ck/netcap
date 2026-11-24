package filter

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// IOC lists are plain text files, one indicator per line, in the iocs folder
// of the netcap config root ($NC_IOC_DIR, else $NC_CONFIG_ROOT/iocs, else
// ~/.config/netcap/iocs). Matching ignores case and surrounding space.
// Lines starting with '#' are comments. Rules name a list by file name only,
// so an expression cannot probe other paths.
const (
	maxIOCListBytes   = 64 << 20
	maxIOCListEntries = 2_000_000
	maxCachedIOCLists = 32
	iocListRecheck    = 30 * time.Second
)

var iocListName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type iocList struct {
	entries map[string]struct{}
	info    os.FileInfo
	checked time.Time
	err     error
}

var (
	iocMu    sync.Mutex
	iocLists = map[string]*iocList{}
	iocDir   string // directory associated with the current cache
)

// IOCDir is the folder InList reads lists from.
func IOCDir() string {
	if dir := os.Getenv("NC_IOC_DIR"); dir != "" {
		return dir
	}
	root := os.Getenv("NC_CONFIG_ROOT")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		root = filepath.Join(home, ".config", "netcap")
	}
	return filepath.Join(root, "iocs")
}

// InList reports whether value is listed in the IOC list file name. A missing
// or invalid list matches nothing; ValidateIOCList reports why.
func InList(value, name string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	list := loadIOCList(name)
	if list == nil || list.err != nil {
		return false
	}
	_, ok := list.entries[value]
	return ok
}

// ValidateIOCList loads a list and returns the error a rule using it would
// otherwise only see as no match.
func ValidateIOCList(name string) error {
	list := loadIOCList(name)
	if list == nil {
		return errors.New("invalid IOC list name")
	}
	return list.err
}

func loadIOCList(name string) *iocList {
	if !iocListName.MatchString(name) {
		return nil
	}
	iocMu.Lock()
	defer iocMu.Unlock()
	dir := IOCDir()
	if dir != iocDir {
		clear(iocLists)
		iocDir = dir
	}
	now := time.Now()
	list := iocLists[name]
	if list != nil && now.Sub(list.checked) < iocListRecheck {
		return list
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return remember(name, &iocList{checked: now, err: err})
	}
	defer root.Close()
	info, err := root.Stat(name)
	if err = checkIOCFile(info, err); err != nil {
		return remember(name, &iocList{checked: now, err: err})
	}
	if list != nil && list.err == nil && os.SameFile(info, list.info) && info.ModTime().Equal(list.info.ModTime()) && info.Size() == list.info.Size() {
		list.checked = now
		return list
	}
	file, err := root.Open(name)
	if err != nil {
		return remember(name, &iocList{checked: now, err: err})
	}
	defer file.Close()
	info, err = file.Stat()
	if err = checkIOCFile(info, err); err != nil {
		return remember(name, &iocList{checked: now, err: err})
	}
	entries, err := readIOCList(file, maxIOCListBytes)
	return remember(name, &iocList{entries: entries, info: info, checked: now, err: err})
}

var errIOCListSize = errors.New("IOC list exceeds byte limit")

func checkIOCFile(info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("IOC list is not a regular file")
	}
	if info.Size() > maxIOCListBytes {
		return errIOCListSize
	}
	return nil
}

func remember(name string, list *iocList) *iocList {
	if _, exists := iocLists[name]; !exists && len(iocLists) >= maxCachedIOCLists {
		var oldest string
		for key, cached := range iocLists {
			if oldest == "" || cached.checked.Before(iocLists[oldest].checked) {
				oldest = key
			}
		}
		delete(iocLists, oldest)
	}
	iocLists[name] = list
	return list
}

func readIOCList(r io.Reader, byteLimit int64) (map[string]struct{}, error) {
	limited := &io.LimitedReader{R: r, N: byteLimit + 1}
	entries := map[string]struct{}{}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 64<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		key := strings.ToLower(line)
		if _, exists := entries[key]; !exists && len(entries) >= maxIOCListEntries {
			return nil, errors.New("IOC list exceeds 2,000,000 entries")
		}
		entries[key] = struct{}{}
	}
	if limited.N == 0 {
		return nil, errIOCListSize
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
