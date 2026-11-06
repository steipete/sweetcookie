package sweetcookie

import (
	"path/filepath"
	"testing"
)

func TestChromiumSnapDir(t *testing.T) {
	if chromiumSnapDir("") != "" {
		t.Fatal("empty home should not invent a snap path")
	}
	home := filepath.Join("/tmp", "home")
	got := chromiumSnapDir(home)
	want := filepath.Join(home, "snap", "chromium", "common", "chromium")
	if got != want {
		t.Fatalf("snap dir = %q, want %q", got, want)
	}
}
