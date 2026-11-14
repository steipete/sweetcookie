//go:build linux && !android

package sweetcookie

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGet_ChromiumSnapPrecedenceAndOverride(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, "config")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("GOOKIE_CHROMIUM_SAFE_STORAGE_PASSWORD", "synthetic-only")
	seed := func(root, value string) string {
		t.Helper()
		path := filepath.Join(root, "Default", "Cookies")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "Local State"), []byte(`{"profile":{"info_cache":{"Default":{"name":"Default"}}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		db := openTestSQLite(t, path)
		if _, err := db.Exec(`CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, value TEXT, encrypted_value BLOB, expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER)`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO cookies VALUES('.example.com','session','/',?,NULL,0,1,1,0)`, value); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	check := func(override, value, path string) {
		t.Helper()
		res, err := Get(context.Background(), Options{URL: "https://example.com/", Browsers: []Browser{BrowserChromium}, Profiles: map[Browser]string{BrowserChromium: override}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Cookies) != 1 || res.Cookies[0].Value != value || res.Cookies[0].Source.StorePath != path {
			t.Fatalf("unexpected result: %#v (warnings=%v)", res.Cookies, res.Warnings)
		}
	}
	snap := seed(filepath.Join(home, "snap", "chromium", "common", "chromium"), "snap")
	check("", "snap", snap)
	xdg := seed(filepath.Join(config, "chromium"), "xdg")
	check("", "xdg", xdg)
	check(snap, "snap", snap)
}
