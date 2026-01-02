package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestChromiumProbeDefaultStoresAndProfileDirOverride(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}

	userData := t.TempDir()
	profileDir := filepath.Join(userData, "Default")
	if err := os.MkdirAll(filepath.Join(profileDir, "Network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Network", "Cookies"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "Cookies"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	stores := chromiumProbeDefaultStores(BrowserChrome, userData)
	if len(stores) != 2 {
		t.Fatalf("want 2 stores got %d", len(stores))
	}

	stores = chromiumResolveFromProfileDir(BrowserChrome, profileDir)
	if len(stores) == 0 {
		t.Fatalf("expected store from profile dir override")
	}
}

func TestChromiumVendorAndEnvMappings_CoverAll(t *testing.T) {
	_ = t
	for _, b := range []Browser{BrowserChrome, BrowserChromium, BrowserEdge, BrowserBrave, BrowserVivaldi, BrowserOpera, "other"} {
		_ = chromiumVendorForBrowser(b)
		_ = envKeySafeStoragePassword(b)
	}
}

func TestGet_DefaultBrowsersAndAllowlist(t *testing.T) {
	res, err := Get(context.Background(), Options{
		URL: "https://example.com/",
		Inline: InlineCookies{
			JSON: []byte(`[{"name":"a","value":"1","domain":"example.com","path":"/"},{"name":"b","value":"2","domain":"example.com","path":"/"}]`),
		},
		Names: []string{"b"},
		Mode:  ModeFirst,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Cookies) != 1 || res.Cookies[0].Name != "b" {
		t.Fatalf("unexpected cookies: %#v", res.Cookies)
	}
}

func TestReadInlineCookies_Empty(t *testing.T) {
	_, _, err := readInlineCookies(InlineCookies{JSON: []byte("   ")})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseInlineExpires_MoreBranches(t *testing.T) {
	if parseInlineExpires(float64(0)) != nil {
		t.Fatal("expected nil for 0")
	}
	if parseInlineExpires(map[string]any{"a": 1}) != nil {
		t.Fatal("expected nil for unsupported type")
	}
	if parseInlineExpires("not-a-time") != nil {
		t.Fatal("expected nil for invalid time string")
	}
}

func TestNormalizeSameSite_MoreBranches(t *testing.T) {
	if normalizeSameSite("Strict") != SameSiteStrict {
		t.Fatal("strict")
	}
	if normalizeSameSite("lax") != SameSiteLax {
		t.Fatal("lax")
	}
	if normalizeSameSite("no_restriction") != SameSiteNone {
		t.Fatal("none")
	}
	if normalizeSameSite("???") != "" {
		t.Fatal("unknown")
	}
}

func TestRemovePKCS7Padding_Errors(t *testing.T) {
	if _, err := removePKCS7Padding([]byte{0x00}); err == nil {
		t.Fatal("expected error for invalid padding length")
	}
	if _, err := removePKCS7Padding([]byte{0x01, 0x02, 0x03, 0x04, 0x05}); err == nil {
		t.Fatal("expected error for invalid padding length")
	}
}

func TestFirefoxResolveCookieDBs_OverridePaths(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cookies.sqlite")
	db := openTestSQLite(t, dbPath)
	if _, err := db.Exec(`CREATE TABLE moz_cookies(host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER)`); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour).Unix()
	if _, err := db.Exec(
		`INSERT INTO moz_cookies(host,name,value,path,expiry,isSecure,isHttpOnly,sameSite) VALUES(?,?,?,?,?,?,?,?)`,
		".example.com", "a", "b", "/", expires, 0, 0, 0,
	); err != nil {
		t.Fatal(err)
	}

	dbs, warnings := firefoxResolveCookieDBs(dbPath)
	if len(warnings) != 0 || len(dbs) != 1 {
		t.Fatalf("unexpected: %v %v", dbs, warnings)
	}

	dirNoCookie := filepath.Join(dir, "profile")
	if err := os.MkdirAll(dirNoCookie, 0o755); err != nil {
		t.Fatal(err)
	}
	dbs, warnings = firefoxResolveCookieDBs(dirNoCookie) // dir override, but missing cookies.sqlite in dir root
	if len(dbs) != 0 || len(warnings) == 0 {
		t.Fatalf("expected warnings for dir override without cookies.sqlite")
	}
}
