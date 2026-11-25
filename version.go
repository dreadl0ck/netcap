// Package netcap is a framework for network traffic analysis. Learn more at https://netcap.io.
package netcap

// Version is the current version identifier for netcap.
var Version = "v0.16.15"

// Commit is the git commit id of the current version.
var Commit = "d1909627e81d0fe888b905b50009ea393a184379"

// GopacketVersion is the version of gopacket library used.
var GopacketVersion = "v1.7.7+v1.1.16-0.20261108153543-61002f918d93"

// BuildIdentity is set with -X by packaged helper builds to
// BuildIdentityFor(Version, Commit). It survives -trimpath, which drops the
// -ldflags build setting, so packagers can verify a helper from its bytes.
var BuildIdentity string

// BuildIdentityFor is the exact byte string a packaged helper embeds.
func BuildIdentityFor(version, commit string) string {
	return "netcap-build-identity/1:" + version + ":" + commit + ";"
}

func init() {
	// Also keeps the stamp reachable, so the linker cannot drop its data.
	if BuildIdentity != "" && BuildIdentity != BuildIdentityFor(Version, Commit) {
		panic("netcap: BuildIdentity does not match Version and Commit")
	}
}
