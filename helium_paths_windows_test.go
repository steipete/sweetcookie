//go:build windows

package sweetcookie

import "testing"

func TestChromiumUserDataDirs_HeliumWindowsUnsupported(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)

	if got := chromiumUserDataDirs(BrowserHelium); len(got) != 0 {
		t.Fatalf("expected no official Helium Windows profile root, got %v", got)
	}
}
