//go:build (darwin && !ios) || (linux && !android)

package sweetcookie

import (
	"os"
	"strings"
)

func chromiumSafeStoragePasswordOverride(b Browser) (string, bool) {
	override := strings.TrimSpace(os.Getenv(envKeySafeStoragePassword(b)))
	return override, override != ""
}
