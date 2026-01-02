//go:build windows

package sweetcookie

import (
	"os"
	"path/filepath"
)

func firefoxRoots() []string {
	if appData := os.Getenv("APPDATA"); appData != "" {
		return []string{filepath.Join(appData, "Mozilla", "Firefox")}
	}
	return nil
}
