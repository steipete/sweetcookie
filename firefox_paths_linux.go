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
		return []string{
			filepath.Join(home, ".zen"),
			filepath.Join(home, ".var", "app", "app.zen_browser.zen", ".zen"),
		}
	case BrowserFloorp:
		return []string{
			filepath.Join(home, ".mozilla", "floorp"),
			filepath.Join(home, ".floorp"),
			filepath.Join(home, ".var", "app", "one.ablaze.floorp", ".floorp"),
		}
	case BrowserWaterfox:
		return []string{
			filepath.Join(home, ".waterfox"),
			filepath.Join(home, ".var", "app", "net.waterfox.waterfox", ".waterfox"),
		}
	case BrowserLibreWolf:
		return []string{
			filepath.Join(home, ".librewolf"),
			filepath.Join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf"),
		}
	default: // BrowserFirefox
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if !filepath.IsAbs(configHome) {
			configHome = filepath.Join(home, ".config")
		}
		return []string{
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
			filepath.Join(configHome, "mozilla", "firefox"),
		}
	}
}
