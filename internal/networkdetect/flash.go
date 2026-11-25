package networkdetect

import (
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type flashReferral struct {
	at   int64
	host string
}

func observedHTTPHost(raw string) string {
	if raw == "" || len(raw) > 8192 {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return ""
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !validDomain(host) {
		return ""
	}
	return host
}

func canonicalHTTPHost(host string) string { return observedHTTPHost("http://" + host) }

func (e *ApplicationEngine) observeFlashDelivery(o ApplicationObservation) (flashReferral, bool) {
	const interval = int64(90 * time.Second)
	if o.Kind != "http" && o.Kind != "flash" {
		return flashReferral{}, false
	}
	host := canonicalHTTPHost(o.Host)
	if host == "" || !globalAddress(o.DstIP) || o.DecryptedTLS {
		return flashReferral{}, false
	}
	key := func(host string) string { return stableKey(o.Scope, o.SrcIP, host) }
	if o.Kind == "flash" {
		seen, ok := e.flashReferral[key(host)]
		return seen, ok && o.At >= seen.at && o.At-seen.at <= interval
	}
	if o.Status < 200 || o.Status >= 400 {
		return flashReferral{}, false
	}
	from, to := o.ReferrerHost, host
	if o.RedirectHost != "" {
		from, to = host, o.RedirectHost
	}
	if from == "" || sameHTTPSite(from, to) {
		return flashReferral{}, false
	}
	if e.flashReferral == nil {
		e.flashReferral = make(map[string]flashReferral)
	}
	if len(e.flashReferral) >= e.config.MaxKeys {
		for k, v := range e.flashReferral {
			if o.At-v.at > interval {
				delete(e.flashReferral, k)
			}
		}
		if len(e.flashReferral) >= e.config.MaxKeys {
			e.Overflow++
			return flashReferral{}, false
		}
	}
	e.flashReferral[key(to)] = flashReferral{o.At, from}
	return flashReferral{}, false
}

func sameHTTPSite(a, b string) bool {
	if a == b {
		return true
	}
	aa, errA := publicsuffix.EffectiveTLDPlusOne(a)
	bb, errB := publicsuffix.EffectiveTLDPlusOne(b)
	return errA == nil && errB == nil && aa == bb
}
