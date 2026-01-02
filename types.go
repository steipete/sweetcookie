package sweetcookie

import "time"

// Browser identifies a cookie source.
type Browser string

const (
	// BrowserInline is the inline cookie payload source.
	BrowserInline Browser = "inline"

	// BrowserChrome is Google Chrome.
	BrowserChrome Browser = "chrome"
	// BrowserChromium is Chromium.
	BrowserChromium Browser = "chromium"
	// BrowserEdge is Microsoft Edge.
	BrowserEdge Browser = "edge"
	// BrowserBrave is Brave Browser.
	BrowserBrave Browser = "brave"
	// BrowserVivaldi is Vivaldi.
	BrowserVivaldi Browser = "vivaldi"
	// BrowserOpera is Opera.
	BrowserOpera Browser = "opera"

	// BrowserFirefox is Mozilla Firefox.
	BrowserFirefox Browser = "firefox"

	// BrowserSafari is Apple Safari (macOS only).
	BrowserSafari Browser = "safari"
)

// Mode controls how results from multiple sources are combined.
type Mode string

const (
	// ModeMerge merges results from all sources.
	ModeMerge Mode = "merge"
	// ModeFirst returns once at least one cookie is found.
	ModeFirst Mode = "first"
)

// SameSite is the cookie SameSite attribute.
type SameSite string

const (
	// SameSiteNone is SameSite=None.
	SameSiteNone SameSite = "None"
	// SameSiteLax is SameSite=Lax.
	SameSiteLax SameSite = "Lax"
	// SameSiteStrict is SameSite=Strict.
	SameSiteStrict SameSite = "Strict"
)

// Source describes where a cookie came from.
type Source struct {
	Browser    Browser
	Profile    string
	StorePath  string
	IsFallback bool
}

// Cookie is a browser cookie record.
type Cookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite SameSite

	Expires *time.Time
	Source  Source
}

// Result is returned by Get.
type Result struct {
	Cookies  []Cookie
	Warnings []string
}

// InlineCookies is an optional cookie payload source (JSON/base64/file).
type InlineCookies struct {
	// Exactly one of these is expected to be set. If multiple are set, JSON wins over Base64 over File.
	JSON   []byte
	Base64 string
	File   string
}

// Options configures cookie loading and filtering.
type Options struct {
	// URL is used to filter cookies by (scheme, host, path).
	// If empty, Origins must be set, or AllowAllHosts must be true.
	URL string

	// Origins are additional origins to consider (e.g. OAuth redirects).
	// If set, they are used for filtering alongside URL.
	Origins []string

	// Names is an allowlist of cookie names (empty means "all names").
	Names []string

	// Browsers is a source priority list. If empty, DefaultBrowsers() is used.
	Browsers []Browser

	// Mode controls how multiple sources are combined.
	Mode Mode

	// Profile overrides per-browser selection.
	// For Chromium-family: profile name (e.g. "Default"), profile dir, or explicit Cookies DB path.
	// For Firefox: profile name/dir, or explicit cookies.sqlite path.
	// For Safari: explicit Cookies.binarycookies path (macOS only).
	Profiles map[Browser]string

	// Inline is an optional source that is always tried before browser reads.
	Inline InlineCookies

	IncludeExpired bool
	AllowAllHosts  bool

	// Timeout for OS helper calls (keychain/keyring).
	Timeout time.Duration

	Debug bool
}

// DefaultBrowsers returns a default source preference order.
func DefaultBrowsers() []Browser {
	return []Browser{
		BrowserChrome,
		BrowserEdge,
		BrowserBrave,
		BrowserChromium,
		BrowserVivaldi,
		BrowserOpera,
		BrowserFirefox,
		BrowserSafari,
	}
}
