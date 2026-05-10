//go:build linux && !android

package sweetcookie

import "testing"

func TestChromiumUserDataDirs_ArcLinuxUnsupported(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if got := chromiumUserDataDirs(BrowserArc); len(got) != 0 {
		t.Fatalf("expected no official Arc Linux profile root, got %v", got)
	}
}
