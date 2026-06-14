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
