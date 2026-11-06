package sweetcookie

import (
	"path/filepath"
	"testing"
)

func TestChromiumLinuxDirsIncludeSnap(t *testing.T) {
	got := chromiumLinuxDirs(BrowserChromium, filepath.Join("/tmp", "xdg"), filepath.Join("/tmp", "home"))
	wantConfig := filepath.Join("/tmp", "xdg", "chromium")
	wantSnap := filepath.Join("/tmp", "home", "snap", "chromium", "common", "chromium")
	if len(got) != 2 || got[0] != wantConfig || got[1] != wantSnap {
		t.Fatalf("chromium dirs = %#v", got)
	}

	if got := chromiumLinuxDirs(BrowserChromium, "", filepath.Join("/tmp", "home")); len(got) != 1 || got[0] != wantSnap {
		t.Fatalf("snap-only dirs = %#v", got)
	}
	if got := chromiumLinuxDirs(BrowserChrome, filepath.Join("/tmp", "xdg"), filepath.Join("/tmp", "home")); len(got) != 3 {
		t.Fatalf("chrome dirs = %#v", got)
	}
}
