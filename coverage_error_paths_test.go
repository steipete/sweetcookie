package sweetcookie

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestChromiumOpenDB_ErrorForMissingFile(t *testing.T) {
	ctx := context.Background()
	_, err := chromiumOpenDB(ctx, filepath.Join(t.TempDir(), "nope.sqlite"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestChromiumOpenSnapshotReadOnly_ErrorForMissingSource(t *testing.T) {
	_, cleanup, _, err := chromiumOpenSnapshotReadOnly(context.Background(), filepath.Join(t.TempDir(), "nope"))
	if cleanup != nil {
		cleanup()
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestChromiumResolveFromCookiesDBPath_Missing(t *testing.T) {
	stores, warnings := chromiumResolveFromCookiesDBPath(BrowserChrome, filepath.Join(t.TempDir(), "nope"))
	if len(stores) != 0 || len(warnings) == 0 {
		t.Fatalf("expected warnings for missing DB")
	}
}

func TestCookieMatchesOrigin_Negatives(t *testing.T) {
	if cookieMatchesOrigin(Cookie{Name: "a", Value: "b", Domain: "example.com", Path: "/a"}, requestOrigin{scheme: "https", host: "other.com", path: "/a"}) {
		t.Fatal("expected domain mismatch")
	}
	if cookieMatchesOrigin(Cookie{Name: "a", Value: "b", Domain: "example.com", Path: "/a"}, requestOrigin{scheme: "https", host: "example.com", path: "/b"}) {
		t.Fatal("expected path mismatch")
	}
}

func TestNormalizePath_NoLeadingSlash(t *testing.T) {
	if got := normalizePath("abc"); got != "/" {
		t.Fatalf("want / got %q", got)
	}
}

func TestSafariReadPage_ErrorBranches(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

	// Short read.
	_, err := safariReadPage(bytes.NewReader([]byte{1, 2, 3}), 0, 10, "x", false)
	if err == nil {
		t.Fatal("expected error")
	}

	// Wrong header.
	page := make([]byte, 0, 12)
	page = append(page, 0, 0, 0, 0)                     // wrong magic
	page = append(page, 1, 0, 0, 0)                     // NumCookies=1
	page = append(page, 12, 0, 0, 0)                    // offset
	page = append(page, bytes.Repeat([]byte{0}, 56)...) // cookie header bytes
	_, err = safariReadPage(bytes.NewReader(page), 0, int32(len(page)), "x", false)
	if err == nil {
		t.Fatal("expected error for bad header")
	}
}

func TestReadFirefoxCookies_NoStore(t *testing.T) {
	res, err := Get(context.Background(), Options{
		URL:      "https://example.com/",
		Browsers: []Browser{BrowserFirefox},
		Profiles: map[Browser]string{BrowserFirefox: filepath.Join(t.TempDir(), "missing")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 0 {
		t.Fatalf("expected no cookies")
	}
	found := false
	for _, w := range res.Warnings {
		if w == "sweetcookie: Firefox cookie store not found" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected firefox store warning, got %v", res.Warnings)
	}
}

func TestChromiumExpiresUTCToTime_Invalid(t *testing.T) {
	if _, ok := chromiumExpiresUTCToTime(1); ok {
		t.Fatal("expected invalid")
	}
}

func TestMacosReadKeychainPassword_Timeout(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

	binDir := t.TempDir()
	securityPath := filepath.Join(binDir, "security")
	if err := os.WriteFile(securityPath, []byte("#!/bin/sh\nsleep 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	_, err := macosReadKeychainPassword(10*time.Millisecond, "Chrome Safe Storage", "Chrome")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		// execCapture wraps errors; accept any non-nil error.
		return
	}
}
