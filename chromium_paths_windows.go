//go:build windows

package sweetcookie

import (
	"os"
	"path/filepath"
)

func chromiumUserDataDirs(b Browser) []string {
	var roots []string
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		switch b {
		case BrowserInline, BrowserOpera, BrowserFirefox, BrowserSafari:
			// no LOCALAPPDATA store
		case BrowserChrome:
			roots = append(roots, filepath.Join(local, "Google", "Chrome", "User Data"))
		case BrowserChromium:
			roots = append(roots, filepath.Join(local, "Chromium", "User Data"))
		case BrowserEdge:
			roots = append(roots, filepath.Join(local, "Microsoft", "Edge", "User Data"))
		case BrowserBrave:
			roots = append(roots, filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"))
		case BrowserVivaldi:
			roots = append(roots, filepath.Join(local, "Vivaldi", "User Data"))
		}
	}

	// Opera stores its profile in roaming AppData.
	if roam := os.Getenv("APPDATA"); roam != "" && b == BrowserOpera {
		roots = append(roots,
			filepath.Join(roam, "Opera Software", "Opera Stable"),
			filepath.Join(roam, "Opera Software", "Opera GX Stable"),
		)
	}
	return roots
}
