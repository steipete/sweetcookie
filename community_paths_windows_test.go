//go:build windows

package sweetcookie

import (
	"path/filepath"
	"testing"
)

func TestChromiumUserDataDirs_CommunityWindows(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)

	cases := map[Browser]string{
		BrowserComet: filepath.Join(local, "Perplexity", "Comet", "User Data"),
		BrowserWhale: filepath.Join(local, "Naver", "Naver Whale", "User Data"),
	}
	for b, want := range cases {
		got := chromiumUserDataDirs(b)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s: want %q got %v", b, want, got)
		}
	}
}

func TestFirefoxRoots_CommunityWindows(t *testing.T) {
	appData := t.TempDir()
	t.Setenv("APPDATA", appData)

	cases := map[Browser]string{
		BrowserZen:       filepath.Join(appData, "zen"),
		BrowserFloorp:    filepath.Join(appData, "Floorp"),
		BrowserWaterfox:  filepath.Join(appData, "Waterfox"),
		BrowserLibreWolf: filepath.Join(appData, "librewolf"),
	}
	for browser, want := range cases {
		got := firefoxRoots(browser)
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s: want %q got %v", browser, want, got)
		}
	}
}
