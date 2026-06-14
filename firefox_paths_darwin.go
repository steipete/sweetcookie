//go:build darwin && !ios

package sweetcookie

import (
	"os"
	"path/filepath"
)

func firefoxRoots(b Browser) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	base := filepath.Join(home, "Library", "Application Support")

	//nolint:exhaustive // Only gecko forks override the default Firefox roots.
	switch b {
	case BrowserZen:
		return []string{filepath.Join(base, "zen")}
	case BrowserFloorp:
		return []string{filepath.Join(base, "Floorp")}
	case BrowserWaterfox:
		return []string{filepath.Join(base, "Waterfox")}
	case BrowserLibreWolf:
		return []string{filepath.Join(base, "librewolf")}
	default: // BrowserFirefox
		return []string{filepath.Join(base, "Firefox")}
	}
}
