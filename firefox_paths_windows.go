//go:build windows

package sweetcookie

import (
	"os"
	"path/filepath"
)

func firefoxRoots(b Browser) []string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return nil
	}

	//nolint:exhaustive // Only gecko forks override the default Firefox roots.
	switch b {
	case BrowserZen:
		return []string{filepath.Join(appData, "zen")}
	case BrowserFloorp:
		return []string{filepath.Join(appData, "Floorp")}
	case BrowserWaterfox:
		return []string{filepath.Join(appData, "Waterfox")}
	case BrowserLibreWolf:
		return []string{filepath.Join(appData, "librewolf")}
	default: // BrowserFirefox
		return []string{filepath.Join(appData, "Mozilla", "Firefox")}
	}
}
