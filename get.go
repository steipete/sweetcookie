package sweetcookie

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"
)

// ErrNoOrigin is returned when neither URL nor Origins is set and AllowAllHosts is false.
var ErrNoOrigin = errors.New("sweetcookie: URL or Origins required (or AllowAllHosts)")

type requestOrigin struct {
	scheme string
	host   string
	path   string
}

// Get loads cookies from configured sources and returns a filtered, de-duplicated result.
func Get(ctx context.Context, opts Options) (Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Mode == "" {
		opts.Mode = ModeMerge
	}

	origins, err := normalizeOrigins(opts.URL, opts.Origins, opts.AllowAllHosts)
	if err != nil {
		return Result{}, err
	}

	var allowlistNames map[string]struct{}
	if len(opts.Names) > 0 {
		allowlistNames = make(map[string]struct{}, len(opts.Names))
		for _, name := range opts.Names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			allowlistNames[name] = struct{}{}
		}
	}

	browsers := opts.Browsers
	if len(browsers) == 0 {
		browsers = DefaultBrowsers()
	}
	browsers = slices.Compact(browsers)

	var allCookies []Cookie
	var warnings []string

	if inlineAny(opts.Inline) {
		inlineCookies, inlineWarnings, err := readInlineCookies(opts.Inline)
		warnings = append(warnings, inlineWarnings...)
		if err != nil {
			warnings = append(warnings, err.Error())
		} else {
			inlineCookies = filterCookies(origins, allowlistNames, opts.IncludeExpired, inlineCookies)
			allCookies = append(allCookies, inlineCookies...)
			if opts.Mode == ModeFirst && len(allCookies) > 0 {
				return Result{Cookies: dedupeCookies(allCookies), Warnings: warnings}, nil
			}
		}
	}

	for _, b := range browsers {
		cookies, browserWarnings, err := readFromBrowser(ctx, b, origins, opts)
		warnings = append(warnings, browserWarnings...)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}

		cookies = filterCookies(origins, allowlistNames, opts.IncludeExpired, cookies)
		allCookies = append(allCookies, cookies...)
		if opts.Mode == ModeFirst && len(allCookies) > 0 {
			return Result{Cookies: dedupeCookies(allCookies), Warnings: warnings}, nil
		}
	}

	return Result{Cookies: dedupeCookies(allCookies), Warnings: warnings}, nil
}

func normalizeOrigins(urlStr string, originStrs []string, allowAllHosts bool) ([]requestOrigin, error) {
	origins := make([]requestOrigin, 0, 1+len(originStrs))
	if urlStr != "" {
		u, err := url.Parse(urlStr)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "" || u.Hostname() == "" {
			return nil, errors.New("sweetcookie: URL must include scheme and host")
		}
		origins = append(origins, requestOrigin{
			scheme: strings.ToLower(u.Scheme),
			host:   normalizeHost(u.Hostname()),
			path:   normalizePath(u.EscapedPath()),
		})
	}
	for _, o := range originStrs {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "" || u.Hostname() == "" {
			return nil, errors.New("sweetcookie: Origins must include scheme and host")
		}
		origins = append(origins, requestOrigin{
			scheme: strings.ToLower(u.Scheme),
			host:   normalizeHost(u.Hostname()),
			path:   normalizePath(u.EscapedPath()),
		})
	}
	if len(origins) == 0 && !allowAllHosts {
		return nil, ErrNoOrigin
	}
	return origins, nil
}
