//go:build linux && !android

package sweetcookie

import (
	"path/filepath"
	"testing"
)

func TestChromiumUserDataDirsIncludeSnap(t *testing.T) {
	t.Setenv("HOME", filepath.Join("/tmp", "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join("/tmp", "xdg"))
	got := chromiumUserDataDirs(BrowserChromium)
	wantConfig := filepath.Join("/tmp", "xdg", "chromium")
	wantSnap := filepath.Join("/tmp", "home", "snap", "chromium", "common", "chromium")
	if len(got) != 2 || got[0] != wantConfig || got[1] != wantSnap {
		t.Fatalf("chromium dirs = %#v", got)
	}
}
