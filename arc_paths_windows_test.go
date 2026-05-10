//go:build windows

package sweetcookie

import (
	"path/filepath"
	"testing"
)

func TestChromiumUserDataDirs_ArcWindows(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)

	got := chromiumUserDataDirs(BrowserArc)
	want := []string{filepath.Join(local, "Packages", "TheBrowserCompany.Arc_ttt1ap7aakyb4", "LocalCache", "Local", "Arc", "User Data")}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("want %v got %v", want, got)
	}
}
