//go:build darwin && !ios

package sweetcookie

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMacosReadKeychainPassword_ErrorIncludesStderr(t *testing.T) {
	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\necho nope 1>&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	_, err := macosReadKeychainPassword(200*time.Millisecond, "Chrome Safe Storage", "Chrome")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSafariCookieFiles_DefaultLocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p := filepath.Join(home, "Library", "Cookies", "Cookies.binarycookies")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("cook"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, _ := safariCookieFiles("")
	if len(files) == 0 || files[0] != p {
		t.Fatalf("unexpected files: %v", files)
	}
}
