//go:build linux && !android

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

	//nolint:exhaustive // Only gecko forks override the default Firefox roots.
	switch b {
	case BrowserZen:
		return []string{filepath.Join(home, ".zen")}
	case BrowserFloorp:
		return []string{
			filepath.Join(home, ".mozilla", "floorp"),
			filepath.Join(home, ".floorp"),
		}
	case BrowserWaterfox:
		return []string{filepath.Join(home, ".waterfox")}
	case BrowserLibreWolf:
		return []string{filepath.Join(home, ".librewolf")}
	default: // BrowserFirefox
		return []string{filepath.Join(home, ".mozilla", "firefox")}
	}
}
