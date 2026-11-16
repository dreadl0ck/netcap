package software

import "encoding/json"

const maxUserAgentCacheBytes = 1 << 20
const maxUserAgentCacheEntries = 4096

type userAgentCacheEntry struct {
	key  string
	size int
}

var userAgentOrder []userAgentCacheEntry
var userAgentCacheBytes int

// LookupUserAgent caches parser results under a bounded encoded-size budget.
func LookupUserAgent(raw string) *userAgent {
	UserAgentParserMutex.Lock()
	defer UserAgentParserMutex.Unlock()
	if cached, ok := UserAgentCache[raw]; ok {
		return cached
	}
	parsed := ParseUserAgent(raw)
	if parsed == nil {
		return nil
	}
	cacheUserAgentLocked(raw, parsed)
	return parsed
}

func cacheUserAgentLocked(raw string, parsed *userAgent) {
	wire, err := json.Marshal(parsed)
	if err != nil {
		return
	}
	size := len(raw) + len(wire) + 256
	if size > maxUserAgentCacheBytes {
		return
	}
	for len(userAgentOrder) > 0 && (userAgentCacheBytes+size > maxUserAgentCacheBytes || len(UserAgentCache) >= maxUserAgentCacheEntries) {
		oldest := userAgentOrder[0]
		delete(UserAgentCache, oldest.key)
		userAgentCacheBytes -= oldest.size
		copy(userAgentOrder, userAgentOrder[1:])
		userAgentOrder[len(userAgentOrder)-1] = userAgentCacheEntry{}
		userAgentOrder = userAgentOrder[:len(userAgentOrder)-1]
	}
	UserAgentCache[raw] = parsed
	userAgentOrder = append(userAgentOrder, userAgentCacheEntry{key: raw, size: size})
	userAgentCacheBytes += size
}
