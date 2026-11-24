// Package netcap is a framework for network traffic analysis. Learn more at https://netcap.io.
package netcap

// Version is the current version identifier for netcap.
var Version = "v0.16.14"

// Commit is the git commit id of the current version.
var Commit = "4343923060bde866c6516a19d584b2728de9b361"

// GopacketVersion is the version of gopacket library used.
var GopacketVersion = "v1.8.0+v1.1.16-0.20261124230652-18ed914b14fe"

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
