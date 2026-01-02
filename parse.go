package sweetcookie

import (
	"strconv"
	"strings"
)

func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}

func envKeySafeStoragePassword(b Browser) string {
	//nolint:exhaustive // Only Chromium-family browsers map to Safe Storage env overrides.
	switch b {
	case BrowserChrome:
		return "GOOKIE_CHROME_SAFE_STORAGE_PASSWORD"
	case BrowserEdge:
		return "GOOKIE_EDGE_SAFE_STORAGE_PASSWORD"
	case BrowserBrave:
		return "GOOKIE_BRAVE_SAFE_STORAGE_PASSWORD"
	case BrowserChromium:
		return "GOOKIE_CHROMIUM_SAFE_STORAGE_PASSWORD"
	case BrowserVivaldi:
		return "GOOKIE_VIVALDI_SAFE_STORAGE_PASSWORD"
	case BrowserOpera:
		return "GOOKIE_OPERA_SAFE_STORAGE_PASSWORD"
	default:
		return "GOOKIE_SAFE_STORAGE_PASSWORD"
	}
}
