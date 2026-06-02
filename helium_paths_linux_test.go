//go:build linux && !android

package sweetcookie

import "testing"

func TestChromiumUserDataDirs_HeliumLinuxUnsupported(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	if got := chromiumUserDataDirs(BrowserHelium); len(got) != 0 {
		t.Fatalf("expected no official Helium Linux profile root, got %v", got)
	}
}
