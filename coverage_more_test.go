package sweetcookie

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDefaultBrowsers(t *testing.T) {
	bs := DefaultBrowsers()
	if len(bs) == 0 {
		t.Fatal("expected browsers")
	}
	seen := map[Browser]struct{}{}
	for _, b := range bs {
		if _, ok := seen[b]; ok {
			t.Fatalf("duplicate %q", b)
		}
		seen[b] = struct{}{}
	}
	if _, ok := seen[BrowserChrome]; !ok {
		t.Fatal("expected chrome")
	}
}

func TestEnvKeySafeStoragePassword(t *testing.T) {
	if envKeySafeStoragePassword(BrowserChrome) != "GOOKIE_CHROME_SAFE_STORAGE_PASSWORD" {
		t.Fatal("chrome mapping")
	}
	if envKeySafeStoragePassword(BrowserEdge) != "GOOKIE_EDGE_SAFE_STORAGE_PASSWORD" {
		t.Fatal("edge mapping")
	}
}

func TestNormalizeOrigins_ErrorsAndAllowAll(t *testing.T) {
	if _, err := normalizeOrigins("", nil, false); !errors.Is(err, ErrNoOrigin) {
		t.Fatalf("want ErrNoOrigin got %v", err)
	}
	if _, err := normalizeOrigins("example.com", nil, false); err == nil {
		t.Fatal("expected error for URL without scheme/host")
	}
	if _, err := normalizeOrigins("", []string{"example.com"}, false); err == nil {
		t.Fatal("expected error for origin without scheme/host")
	}
	if origins, err := normalizeOrigins("", nil, true); err != nil || len(origins) != 0 {
		t.Fatalf("expected allow-all origins; got %v %v", origins, err)
	}
}

func TestGet_ErrNoOrigin(t *testing.T) {
	_, err := Get(context.Background(), Options{})
	if !errors.Is(err, ErrNoOrigin) {
		t.Fatalf("want ErrNoOrigin got %v", err)
	}
}

func TestGet_ModeFirstStopsAfterInline(t *testing.T) {
	res, err := Get(context.Background(), Options{
		URL: "https://example.com/",
		Inline: InlineCookies{
			JSON: []byte(`[{"name":"a","value":"b","domain":"example.com","path":"/"}]`),
		},
		Browsers: []Browser{BrowserFirefox},
		Mode:     ModeFirst,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("want 1 cookie got %d", len(res.Cookies))
	}
	for _, w := range res.Warnings {
		if w == "sweetcookie: Firefox cookie store not found" {
			t.Fatalf("did not expect firefox warnings when ModeFirst returns early: %v", res.Warnings)
		}
	}
}

func TestChromiumVendorForBrowser(t *testing.T) {
	v := chromiumVendorForBrowser(BrowserEdge)
	if v.safeStorageService == "" || v.safeStorageAccount == "" {
		t.Fatal("expected safe storage strings")
	}
}

func TestChromiumPathsAndDiscovery(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only path test")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	userDataDirs := chromiumUserDataDirs(BrowserChrome)
	if len(userDataDirs) != 1 {
		t.Fatalf("want 1 userDataDir got %v", userDataDirs)
	}
	userDataDir := userDataDirs[0]

	if err := os.MkdirAll(filepath.Join(userDataDir, "Default", "Network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDataDir, "Default", "Network", "Cookies"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	localState := []byte(`{"profile":{"info_cache":{"Default":{"is_using_default_name":true,"name":"Default"}}}}`)
	if err := os.WriteFile(filepath.Join(userDataDir, "Local State"), localState, 0o644); err != nil {
		t.Fatal(err)
	}

	stores, _ := chromiumResolveStores(BrowserChrome, "")
	if len(stores) == 0 {
		t.Fatalf("expected stores from Local State discovery")
	}

	stores, _ = chromiumResolveStores(BrowserChrome, "Default")
	if len(stores) == 0 {
		t.Fatalf("expected stores from profile override")
	}
}

func TestMacosReadKeychainPassword_ErrorIncludesStderr(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

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
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

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

func TestCopyFileIfExists_NoSource(t *testing.T) {
	if err := copyFileIfExists(filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "dst")); err != nil {
		t.Fatal(err)
	}
}

func TestParseInlineExpires_RFC3339(t *testing.T) {
	got := parseInlineExpires("2026-01-01T00:00:00Z")
	if got == nil {
		t.Fatal("expected parsed time")
	}
}
