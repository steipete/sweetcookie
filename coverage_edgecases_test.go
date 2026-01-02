package sweetcookie

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestChromiumUserDataDirs_AllCases(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	for _, b := range []Browser{BrowserChrome, BrowserChromium, BrowserEdge, BrowserBrave, BrowserVivaldi, BrowserOpera, "unknown"} {
		_ = chromiumUserDataDirs(b)
	}
}

func TestCopyFileIfExists_SourceExists(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFileIfExists(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "x" {
		t.Fatalf("unexpected dst: %q", string(got))
	}
}

func TestSafariReadString_InvalidOffset(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	_, err := safariReadString(bytes.NewReader([]byte("abc")), "x", 0, 0)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestChromiumStripHashPrefix_Branches(t *testing.T) {
	if got := chromiumStripHashPrefix([]byte("x"), 24); string(got) != "x" {
		t.Fatal("short should not strip")
	}
	if got := chromiumStripHashPrefix(bytes.Repeat([]byte("a"), 40), 1); len(got) != 40 {
		t.Fatal("old meta should not strip")
	}
}

func TestChromiumDecryptAES256GCM_ErrorBranches(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	if _, err := chromiumDecryptAES256GCM([]byte("x"), key, 0); err == nil {
		t.Fatal("expected error too short")
	}
	if _, err := chromiumDecryptAES256GCM([]byte("xxx0123456789012345678901234567890"), key, 0); err == nil {
		t.Fatal("expected missing prefix error")
	}
}

func TestReadInlineBytes_InvalidBase64(t *testing.T) {
	_, _, err := readInlineCookies(InlineCookies{Base64: "!!!!"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFirefoxRowToCookie_EarlyReturns(t *testing.T) {
	if _, ok := firefoxRowToCookie(firefoxDB{path: "x"}, firefoxRow{}); ok {
		t.Fatal("expected false for empty row")
	}
}

func TestReadSafariCookies_InvalidFile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	p := filepath.Join(t.TempDir(), "Cookies.binarycookies")
	if err := os.WriteFile(p, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Get(context.Background(), Options{
		URL:      "https://example.com/",
		Browsers: []Browser{BrowserSafari},
		Profiles: map[Browser]string{BrowserSafari: p},
		Timeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 0 || len(res.Warnings) == 0 {
		t.Fatalf("expected warnings for invalid safari file")
	}
}
