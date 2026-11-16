//go:build !appstore

package webui

import (
	"debug/buildinfo"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
)

func standaloneCLI() bool {
	build, ok := debug.ReadBuildInfo()
	return ok && build.Path == "github.com/dreadl0ck/netcap/cmd/net" && build.Main.Path == "github.com/dreadl0ck/netcap"
}

// captureHelperCommand preserves the running CLI identity, including a bundled
// ELF loader. GUI/Pro helper lookup keeps its separate packaged identity checks.
func captureHelperCommand() (string, []string) {
	if productionPro || !standaloneCLI() {
		return resolveHelperExecutable(), nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", nil
	}
	build, _ := debug.ReadBuildInfo()
	verify := func(path string) bool {
		if runtime.GOOS != "linux" && path == executable {
			return isExecutableFile(path) && runningImageMapped(path)
		}
		candidate, err := buildinfo.ReadFile(path)
		return err == nil && candidate.String() == build.String() && isExecutableFile(path) && runningImageMapped(path)
	}
	return standaloneCommand(executable, runtime.GOOS, verify)
}

func standaloneCommand(executable, platform string, verify func(string) bool) (string, []string) {
	name := filepath.Base(executable)
	if platform == "linux" && (strings.HasPrefix(name, "ld-linux") || strings.HasPrefix(name, "ld-musl")) {
		library := filepath.Dir(executable)
		binary := filepath.Join(library, "net.bin")
		if !verify(binary) {
			return "", nil
		}
		return executable, []string{"--library-path", library, binary}
	}
	if !verify(executable) {
		return "", nil
	}
	return executable, nil
}
