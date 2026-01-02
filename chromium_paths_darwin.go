//go:build darwin && !ios

package sweetcookie

import (
	"os"
	"path/filepath"
)

func chromiumUserDataDirs(b Browser) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	base := filepath.Join(home, "Library", "Application Support")

	//nolint:exhaustive // Only Chromium-family browsers have user data dirs here.
	switch b {
	case BrowserChrome:
		return []string{filepath.Join(base, "Google", "Chrome")}
	case BrowserChromium:
		return []string{filepath.Join(base, "Chromium")}
	case BrowserEdge:
		return []string{filepath.Join(base, "Microsoft Edge")}
	case BrowserBrave:
		return []string{filepath.Join(base, "BraveSoftware", "Brave-Browser")}
	case BrowserVivaldi:
		return []string{filepath.Join(base, "Vivaldi")}
	case BrowserOpera:
		// Opera uses an app bundle identifier directory.
		return []string{filepath.Join(base, "com.operasoftware.Opera")}
	default:
		return nil
	}
}
