//go:build linux && !android

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
	return []string{filepath.Join(home, ".mozilla", "firefox")}
}
