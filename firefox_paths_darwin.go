//go:build darwin && !ios

package sweetcookie

import (
	"os"
	"path/filepath"
)

func firefoxRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, "Library", "Application Support", "Firefox")}
}
