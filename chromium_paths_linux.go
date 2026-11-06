//go:build linux && !android

package sweetcookie

import (
	"os"
	"path/filepath"
)

func chromiumUserDataDirs(b Browser) []string {
	return chromiumLinuxDirs(b, xdgConfigHome(), userHome())
}

func userHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func xdgConfigHome() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	home := userHome()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config")
}
