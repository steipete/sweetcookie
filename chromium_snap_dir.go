package sweetcookie

import "path/filepath"

func chromiumSnapDir(home string) string {
	if home == "" {
		return ""
	}
	return filepath.Join(home, "snap", "chromium", "common", "chromium")
}
