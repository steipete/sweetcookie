//go:build darwin && !ios

package sweetcookie

import (
	"path/filepath"
	"testing"
)

func TestChromiumUserDataDirs_ArcDarwin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := chromiumUserDataDirs(BrowserArc)
	want := []string{filepath.Join(home, "Library", "Application Support", "Arc", "User Data")}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("want %v got %v", want, got)
	}
}
