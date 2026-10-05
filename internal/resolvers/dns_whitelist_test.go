package resolvers

import "testing"

func TestMissingDNSWhitelistClearsPreviousEntries(t *testing.T) {
	originalPath, originalList := DataBaseFolderPath, dnsWhitelist
	t.Cleanup(func() { DataBaseFolderPath, dnsWhitelist = originalPath, originalList })
	DataBaseFolderPath = t.TempDir()
	dnsWhitelist = map[string]struct{}{"old.test": {}}
	InitDNSWhitelist()
	if IsWhitelistedDomain("old.test") {
		t.Fatal("missing optional whitelist retained old entries")
	}
}
