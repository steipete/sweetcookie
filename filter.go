package sweetcookie

import (
	"strings"
	"time"
)

func filterCookies(origins []requestOrigin, allowlistNames map[string]struct{}, includeExpired bool, cookies []Cookie) []Cookie {
	if len(cookies) == 0 {
		return nil
	}

	now := time.Now()
	out := make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		if allowlistNames != nil {
			if _, ok := allowlistNames[c.Name]; !ok {
				continue
			}
		}
		if !includeExpired && c.Expires != nil && c.Expires.Before(now) {
			continue
		}

		if len(origins) > 0 {
			ok := false
			for _, o := range origins {
				if cookieMatchesOrigin(c, o) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}

		if c.Path == "" {
			c.Path = "/"
		}
		if c.Domain != "" {
			c.Domain = normalizeHost(c.Domain)
		}
		out = append(out, c)
	}

	return out
}

func cookieMatchesOrigin(c Cookie, o requestOrigin) bool {
	if c.Domain == "" || o.host == "" {
		return false
	}
	if !hostMatchesCookieDomain(o.host, c.Domain) {
		return false
	}

	if c.Secure && o.scheme != "https" && o.scheme != "wss" {
		return false
	}

	if !pathMatchesCookiePath(o.path, c.Path) {
		return false
	}

	return true
}

func hostMatchesCookieDomain(host, cookieDomain string) bool {
	host = normalizeHost(host)
	cookieDomain = normalizeHost(cookieDomain)
	if host == "" || cookieDomain == "" {
		return false
	}
	if host == cookieDomain {
		return true
	}
	return strings.HasSuffix(host, "."+cookieDomain)
}

func pathMatchesCookiePath(requestPath, cookiePath string) bool {
	requestPath = normalizePath(requestPath)
	cookiePath = normalizePath(cookiePath)
	if cookiePath == "/" {
		return true
	}
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	if cookiePath[len(cookiePath)-1] == '/' {
		return true
	}
	return len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/'
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, ".")
	return strings.ToLower(host)
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path[0] != '/' {
		return "/"
	}
	return path
}
