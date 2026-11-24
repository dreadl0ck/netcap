package filter

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

func parseIOCEntry(format iocFormat, line string) (string, int64, error) {
	switch format {
	case iocHTTPURL:
		key, _, ok := httpURLKey(line)
		if !ok {
			return "", 0, errors.New("expected an absolute HTTP(S) URL in IOC feed")
		}
		return key, 0, nil
	case iocDomainDate:
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return "", 0, errors.New("expected domain and UTC registration date in IOC feed")
		}
		host := IOCHost(fields[0])
		date, err := time.Parse(time.DateOnly, fields[1])
		if host == "" || registrableDomain(host) != host || err != nil || date.Year() < 1985 || date.Year() >= 2262 {
			return "", 0, errors.New("invalid registrable domain or registration date in IOC feed")
		}
		return host, date.UnixNano(), nil
	default:
		return strings.ToLower(line), 0, nil
	}
}

func parseIOCAuthority(authority string) (host, port string) {
	if len(authority) > 300 || strings.ContainsAny(authority, " /\\@?#\t\r\n") {
		return "", ""
	}
	if name, service, err := net.SplitHostPort(authority); err == nil {
		n, err := strconv.ParseUint(service, 10, 16)
		if err != nil || n == 0 {
			return "", ""
		}
		authority, port = name, strconv.FormatUint(n, 10)
	}
	if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")); err == nil && ip.Zone() == "" {
		return ip.Unmap().String(), port
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(authority, "."))
	if err != nil || len(ascii) > 253 || strings.Contains(ascii, "..") {
		return "", ""
	}
	return strings.ToLower(ascii), port
}

// IOCHost converts observed authority into an exact host-feed lookup key.
func IOCHost(authority string) string {
	host, _ := parseIOCAuthority(authority)
	return host
}

func registrableDomain(host string) string {
	if _, err := netip.ParseAddr(host); err == nil || !strings.Contains(host, ".") {
		return ""
	}
	domain, _ := publicsuffix.EffectiveTLDPlusOne(host)
	return domain
}

func httpURLKey(raw string) (key, authority string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil || strings.Contains(raw, "#") {
		return "", "", false
	}
	host, port := parseIOCAuthority(u.Host)
	if host == "" {
		return "", "", false
	}
	if port == "" || u.Scheme == "http" && port == "80" || u.Scheme == "https" && port == "443" {
		authority = host
		if strings.Contains(host, ":") {
			authority = "[" + host + "]"
		}
	} else {
		authority = net.JoinHostPort(host, port)
	}
	return u.Scheme + "://" + authority + u.RequestURI(), authority, true
}

// HTTPURLInList matches an HTTP request target without changing path or query case.
func HTTPURLInList(host, target, name string) bool {
	if len(target) == 0 || len(target) > 32<<10 || !strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return false
	}
	raw := target
	if strings.HasPrefix(target, "/") {
		if strings.HasPrefix(target, "//") || IOCHost(host) == "" {
			return false
		}
		raw = "http://" + host + target
	}
	key, authority, ok := httpURLKey(raw)
	if !ok {
		return false
	}
	if host != "" {
		scheme, _, _ := strings.Cut(key, ":")
		if _, expected, valid := httpURLKey(scheme + "://" + host); !valid || expected != authority {
			return false
		}
	}
	list := loadIOCFeed(name, iocHTTPURL)
	if list == nil || list.err != nil {
		return false
	}
	_, ok = list.entries[key]
	return ok
}

// DomainAgeDays returns whole days since the supplied registration date, at
// capture time. Unknown or future dates return -1; evaluation is entirely local.
func DomainAgeDays(host string, capturedAt int64, name string) int64 {
	key := registrableDomain(IOCHost(host))
	if key == "" || capturedAt <= 0 {
		return -1
	}
	list := loadIOCFeed(name, iocDomainDate)
	if list == nil || list.err != nil {
		return -1
	}
	date, ok := list.entries[key]
	if !ok || capturedAt < date {
		return -1
	}
	return (capturedAt - date) / int64(24*time.Hour)
}
