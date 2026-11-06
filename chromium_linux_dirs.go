package sweetcookie

import "path/filepath"

func chromiumLinuxDirs(b Browser, configHome, home string) []string {
	switch b {
	case BrowserInline, BrowserArc, BrowserHelium, BrowserDia, BrowserComet, BrowserAtlas,
		BrowserFirefox, BrowserZen, BrowserFloorp, BrowserWaterfox, BrowserLibreWolf, BrowserSafari:
		return nil
	case BrowserChrome:
		if configHome == "" {
			return nil
		}
		return []string{
			filepath.Join(configHome, "google-chrome"),
			filepath.Join(configHome, "google-chrome-beta"),
			filepath.Join(configHome, "google-chrome-unstable"),
		}
	case BrowserChromium:
		var dirs []string
		if configHome != "" {
			dirs = append(dirs, filepath.Join(configHome, "chromium"))
		}
		if home != "" {
			dirs = append(dirs, filepath.Join(home, "snap", "chromium", "common", "chromium"))
		}
		return dirs
	case BrowserEdge:
		if configHome == "" {
			return nil
		}
		return []string{
			filepath.Join(configHome, "microsoft-edge"),
			filepath.Join(configHome, "microsoft-edge-beta"),
			filepath.Join(configHome, "microsoft-edge-dev"),
		}
	case BrowserBrave:
		if configHome == "" {
			return nil
		}
		return []string{
			filepath.Join(configHome, "BraveSoftware", "Brave-Browser"),
			filepath.Join(configHome, "brave-browser"),
		}
	case BrowserVivaldi:
		if configHome == "" {
			return nil
		}
		return []string{filepath.Join(configHome, "vivaldi")}
	case BrowserOpera:
		if configHome == "" {
			return nil
		}
		return []string{filepath.Join(configHome, "opera")}
	case BrowserWhale:
		if configHome == "" {
			return nil
		}
		return []string{filepath.Join(configHome, "naver-whale")}
	}
	return nil
}
