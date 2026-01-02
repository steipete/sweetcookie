//go:build linux && !android

package sweetcookie

import (
	"os"
	"path/filepath"
)

func chromiumUserDataDirs(b Browser) []string {
	base := xdgConfigHome()
	if base == "" {
		return nil
	}

	switch b {
	case BrowserChrome:
		return []string{
			filepath.Join(base, "google-chrome"),
			filepath.Join(base, "google-chrome-beta"),
			filepath.Join(base, "google-chrome-unstable"),
		}
	case BrowserChromium:
		return []string{filepath.Join(base, "chromium")}
	case BrowserEdge:
		return []string{
			filepath.Join(base, "microsoft-edge"),
			filepath.Join(base, "microsoft-edge-beta"),
			filepath.Join(base, "microsoft-edge-dev"),
		}
	case BrowserBrave:
		return []string{
			filepath.Join(base, "BraveSoftware", "Brave-Browser"),
			filepath.Join(base, "brave-browser"),
		}
	case BrowserVivaldi:
		return []string{filepath.Join(base, "vivaldi")}
	case BrowserOpera:
		return []string{filepath.Join(base, "opera")}
	default:
		return nil
	}
}

func xdgConfigHome() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config")
}
